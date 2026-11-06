package main

import "fmt"

// Deterministic login pages, so the form fields match what the POST handlers expect and the realm
// looks authentic. Credentials are checked in Go (only real ones work).

func wpLoginPage(errHTML string) string {
	msg := ""
	if errHTML != "" {
		msg = `<div id="login_error">` + errHTML + `</div>
`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en-US">
<head>
	<meta charset="UTF-8" />
	<meta name="viewport" content="width=device-width,initial-scale=1.0" />
	<title>Log In &lsaquo; Veltrona Logistik &#8212; WordPress</title>
	<link rel='stylesheet' id='dashicons-css' href='/blog/wp-includes/css/dashicons.min.css?ver=5.8.3' media='all' />
	<link rel='stylesheet' id='buttons-css' href='/blog/wp-includes/css/buttons.min.css?ver=5.8.3' media='all' />
	<link rel='stylesheet' id='login-css' href='/blog/wp-admin/css/login.min.css?ver=5.8.3' media='all' />
	<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
</head>
<body class="login no-js login-action-login wp-core-ui locale-en-us">
	<script type="text/javascript">document.body.className = document.body.className.replace('no-js','js');</script>
	<div id="login">
		<h1><a href="https://wordpress.org/" title="Powered by WordPress" tabindex="-1">Veltrona Logistik</a></h1>
		%s<form name="loginform" id="loginform" action="/blog/wp-login.php" method="post">
			<p>
				<label for="user_login">Username or Email Address</label>
				<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" />
			</p>
			<div class="user-pass-wrap">
				<label for="user_pass">Password</label>
				<div class="wp-pwd">
					<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" />
				</div>
			</div>
			<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> <label for="rememberme">Remember Me</label></p>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
				<input type="hidden" name="redirect_to" value="/blog/wp-admin/" />
				<input type="hidden" name="testcookie" value="1" />
			</p>
		</form>
		<p id="nav">
			<a href="/blog/wp-login.php?action=lostpassword">Lost your password?</a>
		</p>
		<p id="backtoblog"><a href="/blog/">&larr; Go to Veltrona Logistik</a></p>
	</div>
</body>
</html>`, msg)
}

func portalLoginPage(errMsg string) string {
	msg := ""
	if errMsg != "" {
		msg = `<div class="alert alert-danger" role="alert">` + htmlEscape(errMsg) + `</div>
`
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="de">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="csrf-token" content="%s">
	<title>Anmelden &middot; Veltrona Connect</title>
	<link href="/css/app.css" rel="stylesheet">
</head>
<body class="bg-light">
	<div class="container">
		<div class="row justify-content-center mt-5">
			<div class="col-md-5">
				<div class="card shadow-sm">
					<div class="card-header text-center"><img src="/img/veltrona-connect.svg" height="38" alt="Veltrona Connect"></div>
					<div class="card-body">
						%s<form method="POST" action="/login">
							<input type="hidden" name="_token" value="%s">
							<div class="form-group mb-3">
								<label for="email">E-Mail-Adresse</label>
								<input id="email" type="email" class="form-control" name="email" required autofocus autocomplete="username">
							</div>
							<div class="form-group mb-3">
								<label for="password">Passwort</label>
								<input id="password" type="password" class="form-control" name="password" required autocomplete="current-password">
							</div>
							<div class="form-group form-check mb-3">
								<input type="checkbox" class="form-check-input" name="remember" id="remember">
								<label class="form-check-label" for="remember">Angemeldet bleiben</label>
							</div>
							<button type="submit" class="btn btn-primary w-100">Anmelden</button>
							<div class="text-center mt-3"><a href="/password/reset">Passwort vergessen?</a></div>
						</form>
					</div>
				</div>
				<p class="text-center text-muted mt-3 small">&copy; Veltrona Logistics AG &middot; Veltrona Connect</p>
			</div>
		</div>
	</div>
</body>
</html>`, csrfToken(), msg, csrfToken())
}

// csrfToken is a stable-looking per-process token (the value does not matter; the handler ignores it).
var procToken = randomHex(20)

func csrfToken() string { return procToken }

func phpMyAdminPage(errMsg string) string {
	msg := ""
	if errMsg != "" {
		msg = `<div class="error"><img src="/phpmyadmin/themes/dot.gif" title="" alt="" class="icon ic_s_error"> ` + htmlEscape(errMsg) + `</div>
`
	}
	return fmt.Sprintf(`<!DOCTYPE HTML>
<html lang="en" dir="ltr">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
	<meta name="robots" content="noindex,nofollow" />
	<title>phpMyAdmin</title>
	<link rel="stylesheet" type="text/css" href="/phpmyadmin/js/vendor/jquery/jquery-ui.min.css" />
	<link rel="stylesheet" type="text/css" href="/phpmyadmin/themes/pmahomme/css/theme.css" />
</head>
<body class="loginform">
<div class="container">
	<a href="https://www.phpmyadmin.net/" target="_blank" rel="noopener noreferrer" class="logo">
		<img src="/phpmyadmin/themes/pmahomme/img/logo_right.png" alt="phpMyAdmin" /></a>
	<h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin 4.9.5</bdo></h1>
	%s<form method="post" action="/phpmyadmin/index.php" name="login_form" class="login hide js-show" autocomplete="off">
		<fieldset>
			<legend lang="en" dir="ltr">Log in</legend>
			<div class="item">
				<label for="input_username">Username:</label>
				<input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" autocomplete="username" />
			</div>
			<div class="item">
				<label for="input_password">Password:</label>
				<input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" autocomplete="current-password" />
			</div>
			<div class="item">
				<label for="select_server">Server Choice:</label>
				<select name="pma_servername" id="select_server">
					<option value="1" selected="selected">db-prod-01.internal.veltrona-group.com</option>
				</select>
			</div>
		</fieldset>
		<fieldset class="tblFooters">
			<input value="Go" type="submit" id="input_go" />
			<input type="hidden" name="server" value="1" />
			<input type="hidden" name="target" value="index.php" />
		</fieldset>
	</form>
</div>
</body>
</html>`, msg)
}
