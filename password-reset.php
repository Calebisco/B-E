<?php
include 'includes/session.php';

global $token;

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <link rel="stylesheet" href="assets/css/files/bootstrap.min.css">
    <link rel="stylesheet" href="assets/css/files/calendar.min.css">
    <link rel="stylesheet" href="assets/css/files/dataTables.bootstrap.css">
    <link rel="stylesheet" href="assets/css/files/dataTables.fontAwesome.css">
    <link rel="stylesheet" href="assets/css/files/bootstrap-datetimepicker.min.css">
    <link rel="stylesheet" href="assets/css/files/ekko-lightbox.min.css">
    <link rel="stylesheet" href="assets/css/files/font-awesome.min.css">
    <link rel="stylesheet" href="assets/css/files/select2.min.css">
    <link rel="stylesheet" href="assets/css/files/custom.css">

    <title>Student Portal | Password Reset</title>

</head>

<body>

	<div class="preloader"></div>

	<?php if (isset($_SESSION['signedIn']) && $_SESSION['signedIn'] == true) : ?>

	<?php include 'includes/menus/portal_menu.php'; ?>

    <div class="container">

    <form class="form-horizontal form-custom">

    <div class="form-logo text-center">
    <i class="fa fa-graduation-cap"></i>
    </div>

    <hr>
    <p class="feedback-danger text-center">You are already logged in. You don't have to log in again.</p>
    <hr>

	<div class="pull-left">
    <a class="btn btn-success btn-lg" href="home/">Home</a>
    </div>

    <div class="text-right">
    <a class="btn btn-danger btn-lg" href="sign-out/">Sign Out</a>
    </div>

    </form>

	</div>

	<?php include 'includes/footers/footer.php'; ?>

	<?php else : ?>

    <?php include 'includes/menus/menu.php'; ?>

    <div class="container">

    <form class="form-horizontal form-custom" name="signin_form" id="signin_form">

    <div class="form-logo text-center">
	<i class="fa fa-lock"></i>
    </div>

    <hr class="hr-custom">

    <p id="error" class="feedback-danger text-center"></p>
    <p id="error1" class="feedback-danger text-center"></p>
	<p id="success" class="feedback-success text-center"></p>

    <?php if (isset($_GET['token'])) {
    $token = $_GET['token'];
	} ?>

	<div id="hide">

    <div class="form-group">
    <div class="col-xs-12 col-sm-12 full-width">
    <label for="email">Email address<span class="field-required">*</span></label>
    <input class="form-control" type="text" name="email" id="email" placeholder="Enter your email address">
    </div>
    </div>

    <div class="form-group">
    <div class="col-xs-6 col-sm-6 full-width">
    <label for="password">New password<span class="field-required">*</span></label>
    <input class="form-control" type="password" name="password" id="password" placeholder="Enter your new password">
    </div>
    <div class="col-xs-6 col-sm-6 full-width">
    <label for="confirmpwd">Confirm new password<span class="field-required">*</span></label>
    <input class="form-control" type="password" name="confirmpwd" id="confirmpwd" placeholder="Enter your new password confirmation">
    </div>
    </div>

    <input class="form-control" type="hidden" name="token" id="token" value="<?php echo $token; ?>">

	</div>

	<hr class="hr-custom">

    <div id="extra-button" class="pull-left">
    <a class="btn btn-info btn-lg" href="/">Sign in</a>
    </div>

    <div class="text-right">
	<button id="FormSubmit" class="btn btn-primary btn-lg" >Continue</button>
    </div>

	<div id="success-button" class="text-center" style="display:none;">
    <a class="btn btn-primary btn-lg" href="/">Sign in</a>
    </div>

    </form>

	</div>

    <?php include 'includes/footers/footer.php'; ?>

	<?php endif; ?>

    <?php include 'assets/js-paths/common-js-paths.php'; ?>

    <script src="assets/js/files/jquery-2.1.3.min.js"></script>
    <script src="assets/js/files/moment.min.js"></script>
    <script src="assets/js/files/bootstrap-datetimepicker.min.js"></script>
    <script src="assets/js/files/bootstrap.min.js"></script>
    <script src="assets/js/files/jquery.dataTables.min.js"></script>
    <script src="assets/js/files/dataTables.bootstrap.js"></script>
    <script src="assets/js/files/select2.min.js"></script>
    <script src="assets/js/files/tileJs.min.js"></script>
    <script src="assets/js/files/html5shiv.min.js"></script>
    <script src="assets/js/files/respond.min.js"></script>
    <script src="assets/js/files/ie10-viewport-bug-workaround.min.js"></script>
    <script src="assets/js/files/ekko-lightbox.min.js"></script>
    <script src="assets/js/files/jstz.min.js"></script>
    <script src="assets/js/files/underscore-min.js"></script>
    <script src="assets/js/files/calendar.min.js"></script>
    <script src="assets/js/files/custom.js"></script>

	<script>

    //Password Reset process
    $("#FormSubmit").click(function (e) {
    e.preventDefault();

	var hasError = false;

	var token = $("#token").val();

    //checking if email is inputted
	var email = $("#email").val();
	if(email === '') {
        $("label[for='email']").empty().append("Please enter an email address.");
        $("label[for='email']").removeClass("feedback-success");
		$("label[for='email']").addClass("feedback-danger");
        $("#email").removeClass("input-success");
        $("#email").addClass("input-danger");
        $("#email").focus();
		hasError = true;
		return false;
	} else {
        $("label[for='email']").empty().append("All good!");
        $("label[for='email']").removeClass("feedback-danger");
        $("label[for='email']").addClass("feedback-success");
        $("#email").removeClass("input-danger");
        $("#email").addClass("input-success");
    }

    //checking if password is inputted
	var password = $("#password").val();
	if(password === '') {
        $("label[for='password']").empty().append("Please enter a password.");
        $("label[for='password']").removeClass("feedback-success");
        $("label[for='password']").addClass("feedback-danger");
        $("#password").removeClass("input-success");
        $("#password").addClass("input-danger");
        $("#password").focus();
		hasError  = true;
		return false;
    } else {
        $("label[for='password']").empty().append("All good!");
        $("label[for='password']").removeClass("feedback-danger");
        $("label[for='password']").addClass("feedback-success");
        $("#password").removeClass("input-danger");
        $("#password").addClass("input-success");
	}

    //checking if password is more than 6 characters long
    password = $("#password").val();
	if (password.length < 6) {
        $("#error1").show();
        $("#error1").empty().append("Passwords must be at least 6 characters long. Please try again.");
        $("label[for='password']").empty().append("Passwords must be at least 6 characters long. Please try again.");
        $("label[for='password']").empty().append("Wait a minute!");
        $("label[for='password']").removeClass("feedback-success");
        $("label[for='password']").addClass("feedback-danger");
        $("#password").removeClass("input-success");
        $("#password").addClass("input-danger");
        $("#password").focus();
		hasError  = true;
		return false;
	} else {
        $("label[for='password']").empty().append("All good!");
        $("label[for='password']").removeClass("feedback-danger");
        $("label[for='password']").addClass("feedback-success");
        $("#password").removeClass("input-success");
        $("#password").addClass("input-danger");
	}

    //checking if password contains at least one number, one lowercase and one uppercase letter
	var upperCase= new RegExp('[A-Z]');
	var lowerCase= new RegExp('[a-z]');
	var numbers = new RegExp('[0-9]');

    password = $("#password").val();
	if(password.match(upperCase) && password.match(lowerCase) && password.match(numbers)) {
        $("label[for='password']").empty().append("All good!");
        $("label[for='password']").removeClass("feedback-danger");
        $("label[for='password']").addClass("feedback-success");
        $("#password").removeClass("input-danger");
        $("#password").addClass("input-success");
	} else {
        $("#error1").show();
        $("#error1").empty().append("Passwords must contain at least one number,<br>one lowercase and one uppercase letter. Please try again.");
        $("label[for='password']").empty().append("Wait a minute!");
        $("label[for='password']").removeClass("feedback-success");
        $("label[for='password']").addClass("feedback-danger");
        $("#password").removeClass("input-success");
        $("#password").addClass("input-danger");
        $("#password").focus();
		hasError  = true;
		return false;
	}

    //checking if confirmpwd is inputted
	var confirmpwd = $("#confirmpwd").val();
	if(confirmpwd === '') {
        $("label[for='confirmpwd']").empty().append("Please enter a password confirmation.");
        $("label[for='confirmpwd']").removeClass("feedback-success");
        $("label[for='confirmpwd']").addClass("feedback-danger");
        $("#confirmpwd").removeClass("input-success");
        $("#confirmpwd").addClass("input-danger");
        $("#confirmpwd").focus();
		hasError  = true;
		return false;
    } else {
        $("label[for='confirmpwd']").empty().append("All good!");
        $("label[for='confirmpwd']").removeClass("feedback-danger");
        $("label[for='confirmpwd']").addClass("feedback-success");
        $("#confirmpwd").removeClass("input-danger");
        $("#confirmpwd").addClass("input-success");
	}

    //checking if password and password confirmation match
	if(password != confirmpwd) {
        $("#error1").show();
        $("#error1").empty().append("Your password and confirmation do not match. Please try again.");
        $("label[for='confirmpwd']").empty().append("Wait a minute!");
        $("label[for='confirmpwd']").removeClass("feedback-success");
        $("label[for='confirmpwd']").addClass("feedback-danger");
        $("#confirmpwd").removeClass("input-success");
        $("#confirmpwd").addClass("input-danger");
        $("#confirmpwd").focus();
        hasError  = true;
		return false;
	} else {
        $("label[for='confirmpwd']").empty().append("All good!");
        $("label[for='confirmpwd']").removeClass("feedback-danger");
        $("label[for='confirmpwd']").addClass("feedback-success");
        $("#confirmpwd").removeClass("input-danger");
        $("#confirmpwd").addClass("input-success");
        $("#error1").hide();
	}

    //If there are no errors, initialize the Ajax call
	if(hasError == false){
    jQuery.ajax({
	type: "POST",

    //URL to POST data to
	url: "https://sms.org/includes/processes.php",

    //Data posted
    data:'rp_token=' + token + '&rp_email=' + email + '&rp_password=' + password,

    //If action completed, do the following
    success:function(){
        $("#hide").hide();
		$("#extra-button").hide();
		$("#FormSubmit").hide();
        $(".fa").removeClass("fa-lock");
        $(".fa").addClass("fa-key");
		$("#success").append('Your password has been reset successfully. You can now Sign in with your new password.');
		$("#success-button").show();
    },

    //If action failed, do the following
    error:function (xhr, ajaxOptions, thrownError){
		$("#error").show();
        $("#error").empty().append(thrownError);
    }
	});
    }
	return true;
	});
	</script>

</body>
</html>
