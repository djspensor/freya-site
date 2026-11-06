<?php
declare(strict_types=1);
require_once __DIR__.'/retention.php';
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
function maintenance_reply(int $status,array $data): void {http_response_code($status);echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);exit;}
try{
 $host=strtolower(explode(':',$_SERVER['HTTP_HOST']??'')[0]);$local=in_array($host,['localhost','127.0.0.1'],true);
 if(!$local&&($host!=='freya-design.ru'||!freya_https()))maintenance_reply(403,['error'=>'Forbidden']);
 if(($_SERVER['REQUEST_METHOD']??'GET')!=='POST')maintenance_reply(405,['error'=>'Method not allowed']);
 $keyPath=freya_private().'/maintenance.key';if(!is_file($keyPath)||is_link($keyPath))maintenance_reply(503,['error'=>'Maintenance not configured']);
 $key=trim(file_get_contents($keyPath));$supplied=$_SERVER['HTTP_X_FREYA_MAINTENANCE']??'';
 if(!preg_match('/^[a-f0-9]{64}$/',$key)||!hash_equals($key,$supplied))maintenance_reply(403,['error'=>'Forbidden']);
 $orders=freya_purge_inquiries();$consents=freya_purge_consents();
 if(!$orders['blockedRecords'])freya_locked('maintenance-state.json',static function(&$state){$state=['lastSuccessAt'=>gmdate('c')];});
 maintenance_reply($orders['blockedRecords']?503:200,['ok'=>$orders['blockedRecords']===0,'inquiries'=>$orders,'consents'=>$consents]);
}catch(Throwable $e){error_log('FREYA maintenance failed: '.get_class($e));maintenance_reply(503,['error'=>'Maintenance failed']);}
