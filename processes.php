<?php
include 'session.php';
include 'functions.php';

//Call External functions
//Call ContactUs function
if (isset($_POST["contact_firstname"], $_POST["contact_surname"], $_POST["contact_email"], $_POST["contact_message"])) {
    ContactUs();
}

/////////////////////////////////////////////////////////////////////////////////////////////////////

//Call SignIn function
elseif (isset($_POST['email'], $_POST['password'])) {
	SignIn();
    
}

//////////////////////////////////////////////////////////////////////////////////////////////////

//Call Register function
//Call Register function
elseif(isset(
    $_POST["register_firstname"],
    $_POST["register_surname"],
    $_POST["register_gender"],
    $_POST["register_email"],
    $_POST["register_password"])) {
	Register();
}

//////////////////////////////////////////////////////////////////////////////////////////////////

//Call Forgotten Password/Password Reset functions
//Call SendPasswordToken function
elseif (isset($_POST["fp_email"])) {
	SendPasswordToken();
}

//Call ResetPassword function
elseif (isset($_POST["rp_token"], $_POST["rp_email"], $_POST["rp_password"])) {
	ResetPassword();
}

?>