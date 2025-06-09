<?php
include 'session.php';

//External functions
//ContactUs function
function ContactUs() {

    //Gather posted data and assign variables
    $firstname = filter_input(INPUT_POST, 'contact_firstname', FILTER_SANITIZE_STRING);
	$surname = filter_input(INPUT_POST, 'contact_surname', FILTER_SANITIZE_STRING);
	$email = filter_input(INPUT_POST, 'contact_email', FILTER_SANITIZE_EMAIL);
	$email = filter_var($email, FILTER_VALIDATE_EMAIL);
	$message1 = filter_input(INPUT_POST, 'contact_message', FILTER_SANITIZE_STRING);

    //Check if email address is valid
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		header('HTTP/1.0 550 The email address you entered is invalid.');
		exit();
	}

    //Create email

	//email subject
	$subject = 'New Message';

    //email recipient
    $to = 'contact@sms.org';

	//message
	$message = '<html>';
	$message .= '<body>';
	$message .= '<p>The following person contacted Student Portal:</p>';
	$message .= '<table rules="all" align="center" cellpadding="10" style="color: #333333; background-color: #F0F0F0; border: 1px solid #CCCCCC;">';
	$message .= "<tr><td style=\"border: 1px solid #CCCCCC;\"><strong>First name:</strong> </td><td style=\"border: 1px solid #CCCCCC;\">$firstname</td></tr>";
	$message .= "<tr><td style=\"border: 1px solid #CCCCCC;\"><strong>Surname:</strong> </td><td style=\"border: 1px solid #CCCCCC;\"> $surname</td></tr>";
	$message .= "<tr><td style=\"border: 1px solid #CCCCCC;\"><strong>Email:</strong> </td><td style=\"border: 1px solid #CCCCCC;\"> $email</td></tr>";
	$message .= "<tr><td style=\"border: 1px solid #CCCCCC;\"><strong>Message:</strong> </td><td style=\"border: 1px solid #CCCCCC;\"> $message1</td></tr>";
	$message .= '</table>';
	$message .= '</body>';
	$message .= '</html>';

	//email headers
	$headers  = 'MIME-Version: 1.0'."\r\n";
	$headers .= 'Content-type: text/html; charset=iso-8859-1'."\r\n";
	$headers .= 'From: Student Portal '.$email.''."\r\n";
	$headers .= 'Reply-To: Student Portal '.$email.''."\r\n";

	//Send the email
	mail($to, $subject, $message, $headers);

}

//////////////////////////////////////////////////////////////////////////////////////////

//SignIn function
function SignIn() {

    //Global variables
	global $mysqli;
	global $session_userid;
    global $updated_on;

    //Gather posted data and assign variables
	$email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $email = filter_var($email, FILTER_VALIDATE_EMAIL);
	$password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    //Check if email address is valid
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header('HTTP/1.0 550 The email address you entered is invalid.');
        exit();

    } else {

        //Check if email address exists in the system
        $stmt1 = $mysqli->prepare("SELECT s.userid, s.account_type, s.password, d.user_status FROM user_signin s LEFT JOIN user_detail d ON s.userid=d.userid WHERE s.email=? LIMIT 1");
        $stmt1->bind_param('s', $email);
        $stmt1->execute();
        $stmt1->store_result();
        $stmt1->bind_result($userid, $session_account_type, $db_password, $user_status);
        $stmt1->fetch();

        //If the email address exists, do the following
        if ($stmt1->num_rows == 1) {

        //If the account is active, do the following
        if ($user_status === 'active') {

        //Check if password entered matches the password in the database
        if (password_verify($password, $db_password)) {

            $isSignedIn = 1;

            //Update database to set the signed in flag to 1
            $stmt3 = $mysqli->prepare("UPDATE user_signin SET isSignedIn=?, updated_on=? WHERE userid=? LIMIT 1");
            $stmt3->bind_param('isi', $isSignedIn, $updated_on, $userid);
            $stmt3->execute();
            $stmt3->close();

            //Set sign in session variable to true
            $_SESSION['signedIn'] = true;

            //Escape the session variable
            $session_userid = preg_replace("/[^a-zA-Z0-9_\-]+/", "", $userid);

            //assign variables to session variables
            $_SESSION['session_userid'] = $session_userid;
            $_SESSION['account_type'] = $session_account_type;

        //Otherwise, if password entered doesn't match the password in the database, do the following:
	    } else {
            $stmt1->close();
            header('HTTP/1.0 550 The password you entered is incorrect.');
            exit();
	    }
            //Otherwise, if the account is not active, do the following
        } else {
            $stmt1->close();
            header('HTTP/1.0 550 This account is deactivated. Please contact your system administrator.');
            exit();
        }
        //Otherwise, if the email address doesn't exist, do the following
        } else {
            $stmt1->close();
            header('HTTP/1.0 550 The email address you entered is incorrect.');
            exit();
        }

	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////

//SignOut function
function SignOut() {

    //Global variables
    global $mysqli;
    global $session_userid;
    global $updated_on;

    //Set sign in value to a variable
    $isSignedIn = 0;

    //Update database to set the signed in flag to 0
    $stmt1 = $mysqli->prepare("UPDATE user_signin SET isSignedIn=?, updated_on=? WHERE userid=? LIMIT 1");
    $stmt1->bind_param('isi', $isSignedIn, $updated_on, $session_userid);
    $stmt1->execute();
    $stmt1->close();

    //Unset the session
    session_unset();
    //Destroy the session
    session_destroy();
    //Redirect to the Sign In page
    header('Location: login.php');
}
/////////////////////////////////////////////////////////////////////////////////////////////////////

//Register function
function Register() {

    //Global variables
	global $mysqli;
	global $created_on;

    //Gather posted data and assign variables
	$firstname = filter_input(INPUT_POST, 'register_firstname', FILTER_SANITIZE_STRING);
	$surname = filter_input(INPUT_POST, 'register_surname', FILTER_SANITIZE_STRING);
	$gender = filter_input(INPUT_POST, 'register_gender', FILTER_SANITIZE_STRING);
	$email = filter_input(INPUT_POST, 'register_email', FILTER_SANITIZE_EMAIL);
    $email = filter_var($email, FILTER_VALIDATE_EMAIL);
	$password = filter_input(INPUT_POST, 'register_password', FILTER_SANITIZE_STRING);

    if(empty($firstname)) {
        $_SESSION['message'] = "<div class='alert alert-danger'>Enter a name for the post.</div>";
        header('location:register.php');
    }
    //Check if email address is valid
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header('HTTP/1.0 550 The email address you entered is invalid.');
        exit();
    } else {

        // Check if the e-mail address exists
        $stmt1 = $mysqli->prepare("SELECT userid FROM user_signin WHERE email = ? LIMIT 1");
        $stmt1->bind_param('s', $email);
        $stmt1->execute();
        $stmt1->store_result();
        $stmt1->bind_result($db_userid);
        $stmt1->fetch();

        //If e-mail address already exists, do the following
        if ($stmt1->num_rows == 1) {
            $stmt1->close();
            header('HTTP/1.0 550 An account with the email address entered already exists.');
            exit();
        }

        //Creating account
        $account_type = 'student';
        $password_hash = password_hash($password, PASSWORD_BCRYPT);

        $stmt2 = $mysqli->prepare("INSERT INTO user_signin (account_type, email, password, created_on) VALUES (?, ?, ?, ?)");
        $stmt2->bind_param('ssss', $account_type, $email, $password_hash, $created_on);
        $stmt2->execute();
        $stmt2->close();

        //Creating account
        $gender = strtolower($gender);
        $user_status = 'active';

        $stmt3 = $mysqli->prepare("INSERT INTO user_detail (firstname, surname, gender, user_status, created_on) VALUES (?, ?, ?, ?, ?)");
        $stmt3->bind_param('sssss', $firstname, $surname, $gender, $user_status, $created_on);
        $stmt3->execute();
        $stmt3->close();

        //Creating token
        $token = null;

        $stmt5 = $mysqli->prepare("INSERT INTO user_token (token) VALUES (?)");
        $stmt5->bind_param('s', $token);
        $stmt5->execute();
        $stmt5->close();

        //Creating fees
        $fee_amount = '';

        $stmt6 = $mysqli->prepare("INSERT INTO user_fee (fee_amount, created_on) VALUES (?, ?)");
        $stmt6->bind_param('is', $fee_amount, $created_on);
        $stmt6->execute();
        $stmt6->close();

	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////

//SendPasswordToken function
function SendPasswordToken() {

    //Global variables
	global $mysqli;
	global $created_on;

    //Gather data and assign variables
    $email = filter_input(INPUT_POST, 'fp_email', FILTER_SANITIZE_EMAIL);
	$email = filter_var($email, FILTER_VALIDATE_EMAIL);

    //Check if email address is valid
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		header('HTTP/1.0 550 The email address you entered is invalid.');
		exit();
	}

	//Check if the user exists
	$stmt1 = $mysqli->prepare("SELECT userid FROM user_signin WHERE email = ? LIMIT 1");
	$stmt1->bind_param('s', $email);
	$stmt1->execute();
	$stmt1->store_result();
	$stmt1->bind_result($userid);
	$stmt1->fetch();

    //If the user exists, do the following
	if ($stmt1->num_rows == 1) {

        //Create token
		$uniqueid = uniqid(true);
		$token = password_hash($uniqueid, PASSWORD_BCRYPT);

		$stmt2 = $mysqli->prepare("UPDATE user_token SET token = ?, created_on = ? WHERE userid = ? LIMIT 1");
		$stmt2->bind_param('ssi', $token, $created_on, $userid);
		$stmt2->execute();
		$stmt2->close();

        //Creating link to be sent to the user
		$passwordlink = "<a href=https://sms.org/password-reset/?token=$token>here</a>";

        //Get firstname, surname using userid
        $stmt3 = $mysqli->prepare("SELECT firstname, surname FROM user_detail WHERE userid = ? LIMIT 1");
        $stmt3->bind_param('i', $userid);
        $stmt3->execute();
        $stmt3->store_result();
        $stmt3->bind_result($firstname, $surname);
        $stmt3->fetch();
        $stmt3->close();

        //Create email

		//email subject
		$subject = 'Request to change your password';

		//email message
		$message = '<html>';
		$message .= '<head>';
		$message .= '<title>Student Portal | Password Reset</title>';
		$message .= '</head>';
		$message .= '<body>';
		$message .= "<p>Dear $firstname,</p>";
		$message .= '<p>We have received a request to reset the password for your account.</p>';
		$message .= "<p>To proceed please click $passwordlink.</p>";
		$message .= '<p>If you did not submit this request, please ignore this email.</p>';
		$message .= '<p>Kind Regards,<br>The Student Portal Team</p>';
		$message .= '</body>';
		$message .= '</html>';

        //email headers
		$headers  = 'MIME-Version: 1.0'."\r\n";
		$headers .= 'Content-type: text/html; charset=iso-8859-1'."\r\n";
		$headers .= 'From: Student Portal <admin@sms.org>'."\r\n";
		$headers .= 'Reply-To: Student Portal <admin@sms.org>'."\r\n";

		//Send mail
		mail($email, $subject, $message, $headers);

		$stmt1->close();
	}

    //If the user doesn't exist, do the following
	else {
		header('HTTP/1.0 550 The email address you entered is incorrect.');
        exit();
    }
}
/////////////////////////////////////////////////////////////////////////////////////////////////////

//ResetPassword function
function ResetPassword() {

    //Global variables
	global $mysqli;
	global $updated_on;

    //Gather data and assign variables
	$token = $_POST["rp_token"];
	$email = filter_input(INPUT_POST, 'rp_email', FILTER_SANITIZE_EMAIL);
	$email = filter_var($email, FILTER_VALIDATE_EMAIL);
	$password = filter_input(INPUT_POST, 'rp_password', FILTER_SANITIZE_STRING);

    //Check if email address is valid
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		header('HTTP/1.0 550 The email address you entered is invalid.');
		exit();
	}

    //Check if user exists
	$stmt1 = $mysqli->prepare("SELECT userid FROM user_signin WHERE email = ? LIMIT 1");
	$stmt1->bind_param('s', $email);
	$stmt1->execute();
	$stmt1->store_result();
	$stmt1->bind_result($userid);
	$stmt1->fetch();

    //If the user doesn't exist, do the following
    if ($stmt1->num_rows == 0) {
        $stmt1->close();
        header('HTTP/1.0 550 The email address you entered is invalid.');
        exit();

    //If the user exists, do the following
    } else {

        //Get token from database
        $stmt2 = $mysqli->prepare("SELECT user_token.token, user_detail.firstname FROM user_token LEFT JOIN user_detail ON user_token.userid=user_detail.userid WHERE user_token.userid = ? LIMIT 1");
        $stmt2->bind_param('i', $userid);
        $stmt2->execute();
        $stmt2->store_result();
        $stmt2->bind_result($db_token, $firstname);
        $stmt2->fetch();

        //If the client side token and database token match, do the following
        if ($token === $db_token) {

        //Hash the password
        $password_hash = password_hash($password, PASSWORD_BCRYPT);

            //Change the password
            $stmt4 = $mysqli->prepare("UPDATE user_signin SET password = ?, updated_on = ? WHERE email = ? LIMIT 1");
            $stmt4->bind_param('sss', $password_hash, $updated_on, $email);
            $stmt4->execute();
            $stmt4->close();

            //Empty token record
            $empty_token = NULL;
            $empty_created_on = NULL;

            $stmt4 = $mysqli->prepare("UPDATE user_token SET token = ?, created_on = ? WHERE userid = ? LIMIT 1");
            $stmt4->bind_param('ssi', $empty_token, $empty_created_on, $userid);
            $stmt4->execute();
            $stmt4->close();

            //Create email

            //email subject
            $subject = 'Password reset successfully';

            //email message
            $message = '<html>';
            $message .= '<head>';
            $message .= '<title>Student Portal | Account</title>';
            $message .= '</head>';
            $message .= '<body>';
            $message .= "<p>Dear $firstname,</p>";
            $message .= '<p>Your password has been successfully reset.</p>';
            $message .= '<p>If this action wasn\'t performed by you, please contact Student Portal as soon as possible, by clicking <a href="mailto:contact@sms.org">here</a>.';
            $message .= '<p>Kind Regards,<br>The Student Portal Team</p>';
            $message .= '</body>';
            $message .= '</html>';

            //email headers
            $headers = 'MIME-Version: 1.0'."\r\n";
            $headers .= 'Content-type: text/html; charset=iso-8859-1'."\r\n";
            $headers .= 'From: Student Portal <admin@sms.org>'."\r\n";
            $headers .= 'Reply-To: Student Portal <admin@sms.org>'."\r\n";

            //Send the email
            mail($email, $subject, $message, $headers);

        //If the client side token and database token do not match, do the following
        } else {
            header('HTTP/1.0 550 The password reset key is invalid.');
            exit();
        }
    }
}

function rand_string($length) {
      $str="";
      $chars = "abcdefghijklmanopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      $size = strlen($chars);
      for($i = 0;$i < $length;$i++) {
       $str .= $chars[rand(0,$size-1)];
      }
      return $str; /*  */
}

function rand(){
    $a="a-z";
    $b="0-9"

    rand($a.$b)

}
////////////////////////////////////////////////////////////////////////////////////////////

?>