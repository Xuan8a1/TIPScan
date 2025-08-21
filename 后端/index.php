<?php
header('Content-Type: application/json; charset=utf-8');

define('DB_FILE', __DIR__ . '/data/db.json');
if (!is_dir(__DIR__ . '/data')) {
    mkdir(__DIR__ . '/data', 0777, true);
}
if (!file_exists(DB_FILE)) {
    file_put_contents(DB_FILE, '{}');
}

function read_db() {
    return json_decode(file_get_contents(DB_FILE), true);
}

function write_db($d) {
    file_put_contents(DB_FILE, json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}

function json_out($arr, int $code = 200) {
    http_response_code($code);
    echo json_encode($arr, JSON_UNESCAPED_UNICODE);
    exit;
}

$base = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
$uri  = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($base !== '' && strpos($uri, $base) === 0) {
    $uri = substr($uri, strlen($base));
}
$method = $_SERVER['REQUEST_METHOD'];
$path   = explode('/', trim($uri, '/'));
$db = read_db();

if ($method === 'POST' && $path[0] === 'id' && count($path) === 1) {
    $body = json_decode(file_get_contents('php://input'), true);
    $quota = isset($body['quota']) ? intval($body['quota']) : 1;
    $newId = bin2hex(random_bytes(4));
    $db[$newId] = [
        'quota' => $quota,
        'remaining' => $quota,
        'machines' => []
    ];
    write_db($db);
    json_out(['id' => $newId, 'remaining' => $quota]);
}

if (count($path) < 2 || $path[0] !== 'id') {
    json_out(['error' => 'Bad Request'], 400);
}
$id = $path[1];
if (!isset($db[$id])) {
    json_out(['error' => 'ID not found'], 404);
}

if ($method === 'GET' && count($path) === 2) {
    json_out(['remaining' => $db[$id]['remaining']]);
}

if ($method === 'POST' && isset($path[2]) && $path[2] === 'machine') {
    if ($db[$id]['remaining'] <= 0) {
        json_out(['error' => 'No quota'], 403);
    }
    $body = json_decode(file_get_contents('php://input'), true);
    if (!isset($body['hostname'], $body['data'])) {
        json_out(['error' => 'hostname & data required'], 400);
    }
    $db[$id]['machines'][] = $body;
    $db[$id]['remaining'] -= 1;
    write_db($db);
    json_out(['remaining' => $db[$id]['remaining']]);
}

if ($method === 'GET' && isset($path[2]) && $path[2] === 'data') {
    json_out(['machines' => $db[$id]['machines']]);
}

if ($method === 'DELETE' && count($path) === 2) {
    unset($db[$id]);
    write_db($db);
    json_out(['msg' => 'deleted']);
}

json_out(['error' => 'Not Found'], 404);
?>
