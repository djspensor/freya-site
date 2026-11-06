<?php
declare(strict_types=1);
require_once __DIR__.'/consent-store.php';
function freya_order_guard() {
 $path=freya_private().'/orders-maintenance.lock';$f=fopen($path,'c+');if(!$f||!flock($f,LOCK_EX))throw new RuntimeException('Order maintenance lock unavailable');chmod($path,0600);return $f;
}
function freya_purge_inquiries(): array {
 $guard=freya_order_guard();$removed=0;$legacy=0;$blocked=0;$now=time();
 try{
  foreach(glob(freya_private().'/*.json') as $path){
   if(!preg_match('/^[a-f0-9]{64}\.json$/',basename($path))||is_link($path))continue;
   $f=fopen($path,'r+');if(!$f){$blocked++;continue;}
   try{
    if(!flock($f,LOCK_EX))throw new RuntimeException('Order lock unavailable');
    $record=json_decode(stream_get_contents($f),true,512,JSON_THROW_ON_ERROR);
    if(!is_array($record)||!isset($record['id'],$record['data']))continue;
    if(($record['retentionPolicy']??null)!=='90d-v1'){$legacy++;continue;}
    $review=freya_inquiry_retention($record)['reviewAt'];if(!is_string($review))throw new RuntimeException('Retention date unavailable');
    if(strtotime($review)>$now)continue;
    if(!unlink($path))throw new RuntimeException('Order removal failed');$removed++;
   }catch(Throwable $e){$blocked++;}finally{flock($f,LOCK_UN);fclose($f);}
  }
 }finally{flock($guard,LOCK_UN);fclose($guard);}
 return ['removedInquiries'=>$removed,'legacyRecordsForReview'=>$legacy,'blockedRecords'=>$blocked,'checkedAt'=>gmdate('c',$now)];
}
