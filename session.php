<?php



include 'db_connection.php';

//If session is not set, set session
if (session_status() == PHP_SESSION_NONE) {
	session_cache_limiter('none');
    session_start();
}

global $mysqli;
global $session_userid;

//If session is set, do the following
if (isset($_SESSION['session_userid'])) {
    $session_userid = $_SESSION['session_userid'];

//If session is not set, do the following
} else {
    $session_userid = '';
}

//Get firstname, surname of the currently signed in user
$stmt1 = $mysqli->prepare("SELECT firstname, surname FROM user_detail WHERE userid = ? LIMIT 1");
$stmt1->bind_param('i', $session_userid);
$stmt1->execute();
$stmt1->store_result();
$stmt1->bind_result($session_firstname, $session_surname);
$stmt1->fetch();

//Define dates
date_default_timezone_set('Europe/London');
$created_on = date("Y-m-d G:i:s");
$updated_on = date("Y-m-d G:i:s");
$completed_on = date("Y-m-d G:i:s");
$cancelled_on = date("Y-m-d G:i:s");
$now = date('H:i');
