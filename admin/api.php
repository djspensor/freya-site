<?php
declare(strict_types=1);
require_once dirname(__DIR__).'/api/admin-support.php';
require_once dirname(__DIR__).'/api/consent-store.php';
require_once dirname(__DIR__).'/api/retention.php';
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');header('X-Frame-Options: DENY');
function reply(int $status,array $data): void {http_response_code($status);echo json_encode($data,JSON_UNESCAPED_UNICODE|JSON_INVALID_UTF8_SUBSTITUTE);exit;}
try {
 $host=strtolower(explode(':',$_SERVER['HTTP_HOST']??'')[0]);$local=in_array($host,['127.0.0.1','localhost'],true);
 if(!$local&&($host!=='freya-design.ru'||!freya_https()))reply(403,['error'=>'Используйте защищённый адрес https://freya-design.ru/admin/']);
 $method=$_SERVER['REQUEST_METHOD']??'GET';if(!in_array($method,['GET','POST'],true))reply(405,['error'=>'Метод не поддерживается']);
 if((int)($_SERVER['CONTENT_LENGTH']??0)>16000)reply(413,['error'=>'Слишком большой запрос']);
 session_name('freya_admin');ini_set('session.use_strict_mode','1');session_set_cookie_params(['lifetime'=>0,'path'=>'/admin/','secure'=>!$local,'httponly'=>true,'samesite'=>'Strict']);session_start();
 if(empty($_SESSION['csrf']))$_SESSION['csrf']=bin2hex(random_bytes(32));$csrf=$_SESSION['csrf'];
 $action=$_GET['action']??'';$d=[];
 if($method==='POST'){
  $origin=$local?'http://'.($_SERVER['HTTP_HOST']??''):FREYA_ORIGIN;
  if(($_SERVER['HTTP_ORIGIN']??'')!==$origin||($_SERVER['HTTP_SEC_FETCH_SITE']??'')==='cross-site')reply(403,['error'=>'Недопустимый источник запроса']);
  $d=json_decode(file_get_contents('php://input'),true);if(!is_array($d))reply(400,['error'=>'Неверный формат']);
  if(!hash_equals($csrf,(string)($_SERVER['HTTP_X_CSRF_TOKEN']??'')))reply(403,['error'=>'Обновите страницу']);
 }
 $account=freya_account();$auth=isset($_SESSION['version'],$_SESSION['expires'])&&$_SESSION['version']===$account['version']&&$_SESSION['expires']>time();
 if($method==='GET'&&$action==='session')reply(200,['authenticated'=>$auth,'csrf'=>$csrf,'recoveryEmail'=>FREYA_OWNER]);
 if($action==='login'&&$method==='POST'){
  if(!freya_limit('login:'.($_SERVER['REMOTE_ADDR']??''),10,900)||!freya_limit('login-global',100,900))reply(429,['error'=>'Слишком много попыток. Повторите позже.']);
  $password=$d['password']??'';
  if(!is_string($password)||strlen($password)>256||!$account['hash']||!password_verify($password,$account['hash']))reply(401,['error'=>'Неверный пароль. Для первого входа запросите ссылку восстановления.']);
  session_regenerate_id(true);$_SESSION['version']=$account['version'];$_SESSION['expires']=time()+7200;$_SESSION['csrf']=bin2hex(random_bytes(32));reply(200,['ok'=>true,'csrf'=>$_SESSION['csrf']]);
 }
 if($action==='recover'&&$method==='POST'){
  if(!freya_limit('recover:'.($_SERVER['REMOTE_ADDR']??''),3,900)||!freya_limit('recover-global',3,900))reply(429,['error'=>'Ссылка уже запрашивалась. Проверьте почту или повторите через 15 минут.']);
  $token=bin2hex(random_bytes(32));$hash=hash('sha256',$token);$expires=time()+900;
  freya_locked('account.json',static function(&$a)use($hash,$expires){$a['reset']=['hash'=>$hash,'expires'=>$expires];});
  $link=FREYA_ORIGIN.'/admin/#reset='.$token;
  if(!freya_text_mail('FREYA: установка или восстановление пароля',"Для установки нового пароля откройте ссылку:\n".$link."\n\nСсылка одноразовая, действует 15 минут. Если вы не запрашивали восстановление, просто проигнорируйте письмо.\n")){
   freya_locked('account.json',static function(&$a)use($hash){if(($a['reset']['hash']??'')===$hash)unset($a['reset']);});reply(503,['error'=>'Почтовая служба не приняла письмо. Попробуйте позже.']);
  }
  reply(200,['ok'=>true,'message'=>'Письмо передано почтовой службе. Проверьте почту владельца, включая папку «Спам».']);
 }
 if($action==='reset'&&$method==='POST'){
  if(!freya_limit('reset:'.($_SERVER['REMOTE_ADDR']??''),10,900))reply(429,['error'=>'Слишком много попыток']);
  $token=$d['token']??'';$password=$d['password']??'';
  if(!is_string($token)||!preg_match('/^[a-f0-9]{64}$/',$token)||!is_string($password)||!preg_match('//u',$password)||preg_match_all('/./us',$password)<12||strlen($password)>128)reply(422,['error'=>'Нужна действующая ссылка и пароль от 12 символов (до 128 байт).']);
  $ok=freya_locked('account.json',static function(&$a)use($token,$password){$r=$a['reset']??null;if(!$r||$r['expires']<time()||!hash_equals($r['hash'],hash('sha256',$token)))return false;$a['hash']=password_hash($password,PASSWORD_DEFAULT);$a['version']++;unset($a['reset']);return true;});
  if(!$ok)reply(422,['error'=>'Ссылка недействительна или устарела. Запросите новую.']);$_SESSION=[];session_regenerate_id(true);reply(200,['ok'=>true]);
 }
 if(!$auth)reply(401,['error'=>'Требуется вход']);
 if($action==='logout'&&$method==='POST'){$_SESSION=[];session_destroy();reply(200,['ok'=>true]);}
 if($action==='consents'&&$method==='GET'){
  $offset=filter_var($_GET['offset']??0,FILTER_VALIDATE_INT);if($offset===false||$offset<0)reply(422,['error'=>'Некорректная страница']);
  reply(200,freya_list_consents($offset));
 }
 if($action==='consent'&&$method==='GET'){
  $id=$_GET['id']??'';if(!is_string($id))reply(422,['error'=>'Некорректный номер согласия']);$detail=freya_get_consent($id);
  if(!$detail)reply(404,['error'=>'Запись не найдена или срок её хранения истёк']);
  $available=false;foreach(glob(freya_private().'/*.json') as $file){$r=json_decode(file_get_contents($file),true);if(($r['id']??null)===$detail['consent']['orderId']&&isset($r['data'])){$available=true;break;}}
  $detail['requestAvailable']=$available;reply(200,$detail);
 }
 if($action==='requests'&&$method==='GET'){
  $items=[];foreach(glob(freya_private().'/*.json') as $file){$r=json_decode(file_get_contents($file),true);if(!is_array($r)||!isset($r['id'],$r['data']))continue;unset($r['digest']);$r['retention']=freya_inquiry_retention($r);$items[]=$r;}
  usort($items,static function($a,$b){return strcmp($b['createdAt'],$a['createdAt']);});reply(200,['requests'=>$items,'settings'=>freya_settings()]);
 }
 if($action==='contact'&&$method==='POST'){
  $id=$d['id']??null;if(!is_string($id)||!preg_match('/^F-[0-9]{8}-[A-F0-9]{8}$/',$id))reply(422,['error'=>'Некорректный номер заявки']);
  $guard=freya_order_guard();
  foreach(glob(freya_private().'/*.json') as $file){
   $r=json_decode(file_get_contents($file),true);if(!is_array($r)||($r['id']??null)!==$id||!isset($r['data']))continue;
   $retention=freya_locked(basename($file),static function(&$record)use($id){
    if(($record['id']??null)!==$id||!isset($record['data']))throw new RuntimeException('Request changed');
    $now=time();$record['lastMeaningfulContactAt']=gmdate('c',$now);$record['retentionPolicy']='90d-v1';unset($record['purposeClosedAt']);$record['retentionReviewAt']=gmdate('c',$now+90*86400);freya_update_consent_end($record);
    return freya_inquiry_retention($record);
   });reply(200,['ok'=>true,'retention'=>$retention]);
  }reply(404,['error'=>'Заявка не найдена']);
 }
 if($action==='status'&&$method==='POST'){
  if(!in_array($d['status']??'', ['new','progress','done'],true))reply(422,['error'=>'Некорректный статус']);
  $guard=freya_order_guard();
  foreach(glob(freya_private().'/*.json') as $file){$r=json_decode(file_get_contents($file),true);if(($r['id']??null)!==($d['id']??null))continue;$ok=freya_locked(basename($file),static function(&$r)use($d){$r['workflowStatus']=$d['status'];if($d['status']==='done'&&!isset($r['purposeClosedAt']))$r['purposeClosedAt']=gmdate('c');freya_update_consent_end($r);return true;});reply(200,['ok'=>$ok]);}reply(404,['error'=>'Заявка не найдена']);
 }
 if($action==='settings'&&$method==='POST'){
  if(!is_bool($d['enabled']??null))reply(422,['error'=>'Укажите режим приёма']);
  foreach(['title'=>120,'help'=>500,'button'=>60] as $key=>$limit)if(!is_string($d[$key]??null)||!trim($d[$key])||strlen($d[$key])>$limit*4)reply(422,['error'=>'Проверьте тексты формы']);
  $s=array_intersect_key($d,array_flip(['title','help','button','enabled']));freya_locked('settings.json',static function(&$current)use($s){$current=$s;});reply(200,['ok'=>true]);
 }
 reply(404,['error'=>'Не найдено']);
}catch(Throwable $e){error_log('FREYA admin failure: '.get_class($e));reply(503,['error'=>'Сервис временно недоступен. Повторите позже.']);}
