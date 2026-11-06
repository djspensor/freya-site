<?php
declare(strict_types=1);
require_once __DIR__.'/admin-support.php';
function freya_proof_expiry(int $end): int {return (new DateTimeImmutable('@'.$end))->modify('+3 years')->getTimestamp();}
function freya_consent_document(): array {
 $d=json_decode(file_get_contents(dirname(__DIR__).'/legal/consent.json'),true,512,JSON_THROW_ON_ERROR);
 foreach(['version','title','text'] as $key)if(!is_string($d[$key]??null)||!trim($d[$key]))throw new RuntimeException('Consent document unavailable');
 if(strlen($d['version'])>100||strlen($d['title'])>1000||strlen($d['text'])>150000)throw new RuntimeException('Consent document invalid');
 $d['published']=($d['published']??false)===true;
 $d['hash']=hash('sha256',$d['version']."\n".$d['title']."\n".$d['text']);
 return $d;
}
function freya_consent_transaction(callable $operation) {
 $dir=freya_private().'/consents';
 if(!is_dir($dir)&&!mkdir($dir,0700)&&!is_dir($dir))throw new RuntimeException('Consent storage unavailable');
 if(is_link($dir)||fileowner($dir)!==getmyuid())throw new RuntimeException('Consent storage unavailable');
 chmod($dir,0700);$lock=fopen($dir.'/.lock','c+');
 if(!$lock||!flock($lock,LOCK_EX))throw new RuntimeException('Consent lock unavailable');
 chmod($dir.'/.lock',0600);$temp=null;
 try{
  $path=$dir.'/archive.json';$state=['schema'=>1,'documents'=>[],'records'=>[],'lastCleanupAt'=>null];
  if(is_file($path)){
   $state=json_decode(file_get_contents($path),true,512,JSON_THROW_ON_ERROR);
   if(!is_array($state)||($state['schema']??0)!==1||!is_array($state['documents']??null)||!is_array($state['records']??null))throw new RuntimeException('Consent storage invalid');
  }
  $result=$operation($state);
  $json=json_encode($state,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
  $temp=$dir.'/.write-'.bin2hex(random_bytes(12));$f=fopen($temp,'x');
  if(!$f)throw new RuntimeException('Consent storage unavailable');
  try{chmod($temp,0600);if(fwrite($f,$json)!==strlen($json)||!fflush($f))throw new RuntimeException('Consent storage unavailable');if(function_exists('fsync')&&!fsync($f))throw new RuntimeException('Consent sync failed');}finally{fclose($f);}
  if(!rename($temp,$path))throw new RuntimeException('Consent replace failed');$temp=null;return $result;
 }finally{if($temp&&is_file($temp))unlink($temp);flock($lock,LOCK_UN);fclose($lock);}
}
function freya_consent_prune(array &$state,int $now): array {
 $removed=0;
 foreach($state['records'] as $id=>$r){
  if(!is_int($r['receivedAt']??null)||!is_int($r['expiresAt']??null))throw new RuntimeException('Consent record invalid');
  if(($r['policy']??null)!=='proof-v2')continue; // Legacy records require separate review; never silently delete them under a new policy.
  if(!is_int($r['basisEndAt']??null)||$r['basisEndAt']<$r['receivedAt']||$r['expiresAt']!==freya_proof_expiry($r['basisEndAt']))throw new RuntimeException('Consent proof deadline invalid');
  if($r['expiresAt']<=$now){unset($state['records'][$id]);$removed++;}
 }
 $used=[];foreach($state['records'] as $r)$used[$r['documentHash']]=true;
 $documents=0;foreach($state['documents'] as $hash=>$d)if(!isset($used[$hash])){unset($state['documents'][$hash]);$documents++;}
 $state['lastCleanupAt']=gmdate('c',$now);
 return ['removedRecords'=>$removed,'removedUnreferencedDocuments'=>$documents,'remainingRecords'=>count($state['records']),'checkedAt'=>$state['lastCleanupAt']];
}
function freya_save_consent(string $orderId,array $document): array {
 if(!$document['published'])throw new RuntimeException('Consent not approved');
 return freya_consent_transaction(static function(&$state)use($orderId,$document){
  $now=time();freya_consent_prune($state,$now);
  foreach($state['records'] as $r)if($r['orderId']===$orderId){
   if($r['documentHash']!==$document['hash'])throw new RuntimeException('Consent version conflict');
   return $r;
  }
  $hash=$document['hash'];
  $snapshot=['version'=>$document['version'],'title'=>$document['title'],'text'=>$document['text']];
  if(isset($state['documents'][$hash])&&$state['documents'][$hash]!==$snapshot)throw new RuntimeException('Consent snapshot conflict');
  $state['documents'][$hash]=$snapshot;
  $end=$now+90*86400;
  $r=['policy'=>'proof-v2','basisEndAt'=>$end,'id'=>bin2hex(random_bytes(16)),'orderId'=>$orderId,'receivedAt'=>$now,'expiresAt'=>freya_proof_expiry($end),'documentHash'=>$hash,'version'=>$document['version']];
  $state['records'][$r['id']]=$r;return $r;
 });
}
function freya_consent_summary(array $r): array {$review=($r['policy']??null)!=='proof-v2';return ['id'=>$r['id'],'orderId'=>$r['orderId'],'receivedAt'=>gmdate('c',$r['receivedAt']),'basisEndAt'=>isset($r['basisEndAt'])?gmdate('c',$r['basisEndAt']):null,'expiresAt'=>$review?null:gmdate('c',$r['expiresAt']),'retentionNeedsReview'=>$review,'version'=>$r['version'],'documentHash'=>$r['documentHash']];}
function freya_list_consents(int $offset=0): array {
 return freya_consent_transaction(static function(&$state)use($offset){freya_consent_prune($state,time());$items=array_values($state['records']);usort($items,static function($a,$b){return $b['receivedAt']<=>$a['receivedAt'];});return ['consents'=>array_map('freya_consent_summary',array_slice($items,$offset,100)),'total'=>count($items),'offset'=>$offset,'limit'=>100,'lastCleanupAt'=>$state['lastCleanupAt']];});
}
function freya_get_consent(string $id): ?array {
 if(!preg_match('/^[a-f0-9]{32}$/',$id))return null;
 return freya_consent_transaction(static function(&$state)use($id){freya_consent_prune($state,time());$r=$state['records'][$id]??null;if(!$r)return null;$doc=$state['documents'][$r['documentHash']]??null;if(!$doc)throw new RuntimeException('Consent snapshot missing');if(!hash_equals($r['documentHash'],hash('sha256',$doc['version']."\n".$doc['title']."\n".$doc['text'])))throw new RuntimeException('Consent snapshot integrity failure');return ['consent'=>freya_consent_summary($r),'document'=>$doc];});
}
function freya_purge_consents(): array {return freya_consent_transaction(static function(&$state){return freya_consent_prune($state,time());});}
function freya_update_consent_end(array &$record): void {
 $id=$record['consent']['id']??null;$review=freya_inquiry_retention($record)['reviewAt'];if(!is_string($id)||!is_string($review))return;
 $end=strtotime($review);$expiry=freya_consent_transaction(static function(&$state)use($id,$end){
  $r=$state['records'][$id]??null;if(!$r||($r['policy']??null)!=='proof-v2')return null;
  $end=max($end,$r['receivedAt']);$state['records'][$id]['basisEndAt']=$end;$state['records'][$id]['expiresAt']=freya_proof_expiry($end);return $state['records'][$id]['expiresAt'];
 });if($expiry!==null)$record['consent']['expiresAt']=gmdate('c',$expiry);
}
