<?php
declare(strict_types=1);

// Mail is sent only to the owner's fixed address. No credentials or public order listing.
require_once __DIR__ . '/admin-support.php';
require_once __DIR__ . '/consent-store.php';
const RECIPIENT = FREYA_OWNER;
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function respond(int $status, array $data): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
function bytesLimit(string $value): int {
    $n = (float)$value;
    switch (strtolower(substr(trim($value), -1))) {
        case 'g': $n *= 1024;
        case 'm': $n *= 1024;
        case 'k': $n *= 1024;
    }
    return (int)$n;
}
function field(string $name, int $limit = 500): string {
    $value = $_POST[$name] ?? '';
    if (!is_string($value) || !preg_match('//u', $value) || strlen($value) > $limit * 4) {
        respond(422, ['error' => 'Проверьте поле: ' . $name]);
    }
    return trim($value);
}
function storeRecord($handle, array $record): void {
    $json = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    rewind($handle);
    if (!ftruncate($handle, 0) || fwrite($handle, $json) !== strlen($json) || !fflush($handle)) {
        throw new RuntimeException('Cannot persist order');
    }
}
function checkRate(string $directory): void {
    $handle = fopen($directory . '/rate.json', 'c+');
    if (!$handle || !flock($handle, LOCK_EX)) throw new RuntimeException('Rate storage unavailable');
    chmod($directory . '/rate.json', 0600);
    $state = json_decode(stream_get_contents($handle), true) ?: [];
    $now = time();
    $global = array_values(array_filter($state['global'] ?? [], static function ($t) use ($now) { return $t > $now - 60; }));
    $ips = [];
    foreach (($state['ips'] ?? []) as $key => $times) {
        $recent = array_values(array_filter($times, static function ($t) use ($now) { return $t > $now - 600; }));
        if ($recent) $ips[$key] = $recent;
    }
    $ip = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown', __DIR__);
    if (count($global) >= 10 || count($ips[$ip] ?? []) >= 5) {
        flock($handle, LOCK_UN); fclose($handle);
        header('Retry-After: 600');
        respond(429, ['error' => 'Слишком много запросов. Подождите несколько минут; заполненные данные останутся в форме.']);
    }
    $global[] = $now; $ips[$ip][] = $now;
    storeRecord($handle, ['global' => $global, 'ips' => $ips]);
    flock($handle, LOCK_UN); fclose($handle);
}

try {
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'POST'], true)) respond(405, ['error' => 'Метод не поддерживается']);
    $host = strtolower($_SERVER['HTTP_HOST'] ?? '');
    $hostname = explode(':', $host)[0];
    // Local PHP instances are used by the isolated integration test only.
    if (!in_array($hostname, ['freya-design.ru', 'localhost', '127.0.0.1'], true)) {
        respond(403, ['error' => 'Недопустимый адрес сайта']);
    }
    $scheme = freya_https() ? 'https' : 'http';
    if ($hostname === 'freya-design.ru' && $scheme !== 'https') respond(403, ['error'=>'Используйте HTTPS']);
    if ($method === 'POST') {
        if (($_SERVER['HTTP_ORIGIN'] ?? '') !== $scheme . '://' . $host || ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') === 'cross-site') {
            respond(403, ['error' => 'Отправляйте запрос через форму на сайте FREYA']);
        }
    }
    ini_set('session.use_strict_mode', '1');
    session_name('freya_mail_session');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $scheme === 'https', 'httponly' => true, 'samesite' => 'Strict']);
    if (!session_start()) throw new RuntimeException('Session unavailable');
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    $csrf = $_SESSION['csrf'];
    $session = session_id();
    session_write_close();

    $directory = dirname(__DIR__, 2) . '/.freya-orders';
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Private order storage unavailable');
    }
    if (is_link($directory) || fileowner($directory) !== getmyuid() || !is_writable($directory)) {
        throw new RuntimeException('Private order storage unavailable');
    }
    chmod($directory, 0700);
    $maxFile = min(10 * 1024 * 1024, bytesLimit((string)ini_get('upload_max_filesize')));
    $postLimit = bytesLimit((string)ini_get('post_max_size'));
    if ($postLimit <= 0) $postLimit = 30 * 1024 * 1024;
    $settings = freya_settings();
    $consentDocument = freya_consent_document();
    $maxTotal = min(20 * 1024 * 1024, max(0, $postLimit - 65536));
    $mailReady = function_exists('mail') && !in_array('mail', array_map('trim', explode(',', (string)ini_get('disable_functions'))), true);
    if ($method === 'GET') {
        respond(200, ['enabled' => $mailReady && $settings['enabled'] && $consentDocument['published'] && freya_maintenance_ready(), 'consent'=>['published'=>$consentDocument['published'],'version'=>$consentDocument['version'],'hash'=>$consentDocument['hash'],'url'=>'/legal/consent/'],'settings'=>$settings, 'mode' => 'email', 'recipient' => RECIPIENT, 'csrf' => $csrf,
            'maxFileBytes' => $maxFile, 'maxTotalBytes' => $maxTotal, 'maxFiles' => 3]);
    }
    if (!$consentDocument['published']) respond(503, ['error'=>'Редакция согласия ещё не утверждена. Отправка через форму пока недоступна.']);
    if (!freya_maintenance_ready()) respond(503, ['error'=>'Приём заявок временно недоступен. Повторите позже или свяжитесь с FREYA напрямую.']);
    if (!$settings['enabled']) respond(503, ['error'=>'Приём заявок временно выключен. Напишите на freya.mebel@yandex.ru']);
    if (!$mailReady) respond(503, ['error' => 'Почтовая служба временно недоступна. Данные остаются в форме.']);
    if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > $postLimit) {
        respond(413, ['error' => 'Размер запроса превышает лимит хостинга. Уменьшите вложения или укажите ссылку на материалы.']);
    }
    if (!is_string($_POST['csrf'] ?? null) || !hash_equals($csrf, $_POST['csrf'])) {
        respond(403, ['error' => 'Обновите страницу формы и повторите отправку.']);
    }
    if (field('consentAccepted', 1) !== '1') respond(422, ['error'=>'Для отправки нужно отдельное согласие на обработку персональных данных.']);
    if (field('consentVersion',100) !== $consentDocument['version'] || !hash_equals($consentDocument['hash'], field('consentHash',64))) respond(409, ['error'=>'Редакция согласия изменилась. Обновите страницу, ознакомьтесь с ней и подтвердите согласие заново.']);
    if (field('website', 200) !== '') respond(422, ['error' => 'Не удалось проверить форму.']);
    $submission = field('submissionId', 32);
    if (!preg_match('/^[a-f0-9]{32}$/', $submission)) respond(422, ['error' => 'Обновите страницу формы.']);
    $data = [];
    $limits = ['name'=>100,'contact'=>160,'company'=>160,'role'=>40,'interest'=>100,'objectType'=>120,'quantity'=>160,
        'timing'=>160,'message'=>3000,'question'=>1500,'budget'=>100,'city'=>100,'referenceLink'=>1000,'modelId'=>100,'modelTitle'=>160,'page'=>1000];
    foreach ($limits as $key => $limit) $data[$key] = field($key, $limit);
    $digits = preg_replace('/\D/', '', $data['contact']);
    $email = filter_var($data['contact'], FILTER_VALIDATE_EMAIL);
    $phone = preg_match('/^[+\d().\s-]+$/', $data['contact']) && strlen($digits) >= 7 && strlen($digits) <= 15;
    if (!$data['name'] || !$data['message'] || (!$email && !$phone)) {
        respond(422, ['error' => 'Укажите имя, корректный телефон или email и кратко опишите задачу.']);
    }
    if ($data['referenceLink'] && (!filter_var($data['referenceLink'], FILTER_VALIDATE_URL) || !in_array(strtolower((string)parse_url($data['referenceLink'], PHP_URL_SCHEME)), ['http','https'], true))) {
        respond(422, ['error' => 'Ссылка на материалы должна начинаться с http:// или https://']);
    }
    $attachments = []; $total = 0;
    $files = $_FILES['references'] ?? null;
    if ($files && (!is_array($files['name']) || count($files['name']) > 3)) respond(422, ['error' => 'Выберите не более трёх файлов.']);
    if ($files) {
        $allowed = ['pdf'=>'application/pdf','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','webp'=>'image/webp'];
        foreach ($files['name'] as $i => $name) {
            $error = $files['error'][$i];
            if ($error === UPLOAD_ERR_NO_FILE) continue;
            if ($error !== UPLOAD_ERR_OK) respond(422, ['error' => 'Не удалось загрузить вложение. Уменьшите файл или укажите ссылку.']);
            $tmp = $files['tmp_name'][$i];
            $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            if (!isset($allowed[$extension]) || !is_uploaded_file($tmp) || !class_exists('finfo')) respond(422, ['error' => 'Разрешены только PDF, JPG, PNG и WEBP.']);
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($tmp);
            $size = filesize($tmp); $total += $size;
            if ($mime !== $allowed[$extension] || $size < 1 || $size > $maxFile || $total > $maxTotal) {
                respond(422, ['error' => 'Проверьте формат и размер вложений. Лимиты указаны рядом с полем файлов.']);
            }
            $attachments[] = ['name'=>basename($name),'mime'=>$mime,'bytes'=>$size,'tmp'=>$tmp,'sha256'=>hash_file('sha256',$tmp)];
        }
    }
    $digest = hash('sha256', json_encode([$data, $consentDocument['hash'], array_map(static function ($a) { return [$a['name'],$a['sha256']]; }, $attachments)], JSON_UNESCAPED_UNICODE));
    $recordPath = $directory . '/' . hash('sha256', $session . ':' . $submission) . '.json';
    $handle = fopen($recordPath, 'c+');
    if (!$handle || !flock($handle, LOCK_EX)) throw new RuntimeException('Order lock unavailable');
    chmod($recordPath, 0600);
    $previous = json_decode(stream_get_contents($handle), true);
    if ($previous) {
        if ($previous['digest'] !== $digest) respond(409, ['error' => 'Данные заявки изменились. Обновите форму перед новой отправкой.']);
        if ($previous['status'] === 'accepted') respond(200, ['ok'=>true,'id'=>$previous['id'],'status'=>'accepted','duplicate'=>true]);
        if ($previous['status'] === 'pending') respond(202, ['ok'=>true,'id'=>$previous['id'],'status'=>'pending']);
    }
    checkRate($directory);
    $id = $previous['id'] ?? ('F-' . gmdate('Ymd') . '-' . strtoupper(bin2hex(random_bytes(4))));
    $consent = freya_save_consent($id, $consentDocument);
    $record = ['retentionPolicy'=>'90d-v1','consent'=>['id'=>$consent['id'],'version'=>$consent['version'],'receivedAt'=>gmdate('c',$consent['receivedAt']),'expiresAt'=>gmdate('c',$consent['expiresAt']),'documentHash'=>$consent['documentHash']],'id'=>$id,'createdAt'=>gmdate('c'),'status'=>'pending','digest'=>$digest,'recipient'=>RECIPIENT,'data'=>$data,
        'attachments'=>array_map(static function ($a) { return ['name'=>$a['name'],'bytes'=>$a['bytes'],'sha256'=>$a['sha256']]; }, $attachments)];
    storeRecord($handle, $record);
    $roles = ['personal'=>'Для себя / семьи','designer'=>'Для клиента / дизайн-проекта','business'=>'Для бизнеса / объекта'];
    $labels = ['name'=>'Имя','contact'=>'Контакт','company'=>'Компания','role'=>'Сценарий','interest'=>'Что изготовить','objectType'=>'Пространство',
        'quantity'=>'Количество / объём','timing'=>'Желаемый срок','message'=>'Задача','question'=>'Дополнительный вопрос','budget'=>'Бюджет','city'=>'Город',
        'referenceLink'=>'Ссылка на материалы','modelTitle'=>'Пример для обсуждения','page'=>'Страница формы'];
    $body = "FREYA DESIGN — новая заявка {$id}\n\n";
    foreach ($labels as $key => $label) $body .= $label . ': ' . ($key === 'role' ? ($roles[$data[$key]] ?? 'Не указан') : ($data[$key] ?: 'Не указано')) . "\n\n";
    $body .= 'Вложения: ' . ($attachments ? implode(', ', array_column($attachments, 'name')) : 'Нет') . "\n";
    $boundary = 'freya_' . bin2hex(random_bytes(18));
    $sender = (string)ini_get('sendmail_from');
    if (!filter_var($sender, FILTER_VALIDATE_EMAIL)) $sender = get_current_user() . '@' . php_uname('n');
    if (!filter_var($sender, FILTER_VALIDATE_EMAIL)) $sender = 'noreply@spensoa9.beget.tech';
    $headers = "From: FREYA DESIGN <{$sender}>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"{$boundary}\"";
    if ($email && !preg_match('/[\r\n]/', $data['contact'])) $headers .= "\r\nReply-To: " . $data['contact'];
    $message = "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode($body));
    foreach ($attachments as $attachment) {
        $filename = '=?UTF-8?B?' . base64_encode($attachment['name']) . '?=';
        $message .= "\r\n--{$boundary}\r\nContent-Type: {$attachment['mime']}\r\nContent-Disposition: attachment; filename=\"{$filename}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" . chunk_split(base64_encode(file_get_contents($attachment['tmp'])));
    }
    $message .= "\r\n--{$boundary}--\r\n";
    $subject = '=?UTF-8?B?' . base64_encode('FREYA — заявка ' . $id) . '?=';
    $accepted = mail(RECIPIENT, $subject, $message, $headers);
    $record['status'] = $accepted ? 'accepted' : 'failed';
    $record['mailAttemptAt'] = gmdate('c');
    storeRecord($handle, $record);
    flock($handle, LOCK_UN); fclose($handle);
    if (!$accepted) respond(503, ['error'=>'Почтовая служба не приняла письмо. Данные заявки сохранены на сервере; попробуйте отправить позже.']);
    respond(200, ['ok'=>true,'id'=>$id,'status'=>'accepted']);
} catch (Throwable $error) {
    // Do not expose server paths, user details or mail contents in responses/logs.
    error_log('FREYA order handler failed (' . get_class($error) . ')');
    respond(503, ['error'=>'Не удалось завершить отправку. Заполненные данные остаются в форме. Попробуйте позже.']);
}
