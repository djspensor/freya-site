<?php
declare(strict_types=1);
const FREYA_OWNER = 'freya.mebel@yandex.ru';
const FREYA_ORIGIN = 'https://freya-design.ru';
function freya_https(): bool { return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'; }
function freya_private(): string {
 $dir=dirname(__DIR__,2).'/.freya-orders';
 if(!is_dir($dir)&&!mkdir($dir,0700,true)&&!is_dir($dir))throw new RuntimeException('Storage unavailable');
 if(is_link($dir)||fileowner($dir)!==getmyuid())throw new RuntimeException('Storage unavailable');
 chmod($dir,0700);return $dir;
}
function freya_locked(string $name, callable $fn) {
 $path=freya_private().'/'.$name; $f=fopen($path,'c+');
 if(!$f||!flock($f,LOCK_EX))throw new RuntimeException('Storage unavailable');
 chmod($path,0600);
 try{$data=json_decode(stream_get_contents($f),true)?:[];$result=$fn($data);$json=json_encode($data,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);rewind($f);if(!ftruncate($f,0)||fwrite($f,$json)!==strlen($json)||!fflush($f))throw new RuntimeException('Storage unavailable');return $result;}
 finally{flock($f,LOCK_UN);fclose($f);}
}
function freya_account(): array {return freya_locked('account.json',static function(&$d){if(!$d)$d=['hash'=>null,'version'=>1];return $d;});}
function freya_limit(string $scope,int $count,int $seconds): bool {
 return freya_locked('admin-rate.json',static function(&$d)use($scope,$count,$seconds){$now=time();foreach($d as $k=>$v)if(($v['until']??0)<$now)unset($d[$k]);$key=hash('sha256',$scope);$d[$key]=$d[$key]??['until'=>$now+$seconds,'count'=>0];$d[$key]['count']++;return $d[$key]['count']<=$count;});
}
function freya_sender(): string { $sender=(string)ini_get('sendmail_from');if(!filter_var($sender,FILTER_VALIDATE_EMAIL))$sender=get_current_user().'@'.php_uname('n');return filter_var($sender,FILTER_VALIDATE_EMAIL)?$sender:'noreply@freya-design.ru'; }
function freya_text_mail(string $subject,string $body): bool {return mail(FREYA_OWNER,'=?UTF-8?B?'.base64_encode($subject).'?=',$body,'From: FREYA DESIGN <'.freya_sender().">\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit");}
function freya_settings(): array {return freya_locked('settings.json',static function(&$d){if(!$d)$d=['enabled'=>true,'title'=>'Расскажите о вашем проекте.','help'=>'Достаточно описать задачу. Остальное можно уточнить при обсуждении.','button'=>'Отправить запрос'];return $d;});}
function freya_maintenance_ready(): bool {
 $path=freya_private().'/maintenance-state.json';if(!is_file($path)||is_link($path))return false;
 $state=json_decode(file_get_contents($path),true);$at=is_string($state['lastSuccessAt']??null)?strtotime($state['lastSuccessAt']):false;
 return $at!==false&&$at<=time()+60&&$at>=time()-48*3600;
}
function freya_inquiry_retention(array $record): array {
 $manual=is_string($record['lastMeaningfulContactAt']??null);
 $value=$manual?$record['lastMeaningfulContactAt']:($record['createdAt']??null);
 $time=is_string($value)?strtotime($value):false;
 $end=$time===false?false:$time+90*86400;$closed=is_string($record['purposeClosedAt']??null)?strtotime($record['purposeClosedAt']):false;
 if($end!==false&&$closed!==false)$end=min($end,$closed);
 return ['days'=>90,'lastMeaningfulContactAt'=>$time===false?null:gmdate('c',$time),'source'=>$manual?'manager':'submission','reviewAt'=>$end===false?null:gmdate('c',$end)];
}
