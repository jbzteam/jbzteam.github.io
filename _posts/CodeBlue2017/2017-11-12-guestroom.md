---
layout: post
title:  "CodeBlue CTF 2017 - Guestroom"
date:   2017-11-12 16:35
categories: [CodeBlue2017]
tags: [Web]
author: jbz
---

We are presented with a challenge php based and we have the source code.

Looking at the webpage we have a login and a register form and everything has a reCAPTCHA.

Now that we know some basic stuff, we can analyze the source code of the application.

``` $app->flag = '***CENSORED***'; // Can't guess ```

Ok the flag is in the source code, so no sqli is required and we'll get it if we are not a "guest" user and we are logged in.

```
$app->get('/flag', function () use ($app) {
    if (isset($_SESSION['is_logined']) === false || isset($_SESSION['is_guest']) === true) {
        $app->redirect('/#try+harder');
    }
    return $app->flag;
});
```

Let's see where we become a guest user:

```

$app->post('/login-2fa', function () use ($app) {
    if (isset($_SESSION['id']) === false) {
        $app->redirect('/#missing+login');
    }

    $code = (isset($_POST['code']) === true && $_POST['code'] !== '') ? (string)$_POST['code'] : die('Missing code');

    require_once('libs/PHPGangsta/GoogleAuthenticator.php');
    $ga = new PHPGangsta_GoogleAuthenticator();

    $sth = $app->pdo->prepare('SELECT secret FROM users WHERE id = :id');
    $sth->execute([':id' => $_SESSION['id']]);
    $secret = $sth->fetch()[0];
    if ($ga->verifyCode($secret, $code) === false) {
        $app->redirect('/login-2fa#invalid+auth');
    }

    $sth = $app->pdo->prepare('SELECT authorize FROM acl WHERE id = :id');
    $sth->execute([':id' => $_SESSION['id']]);
    if ($sth->fetch()[0] === 'GUEST') {
        $_SESSION['is_guest'] = true;
    }

    $_SESSION['is_logined'] = true;
    $app->redirect('/#logined');
});

```

This is the relevant part:
```
$sth = $app->pdo->prepare('SELECT authorize FROM acl WHERE id = :id');
    $sth->execute([':id' => $_SESSION['id']]);
    if ($sth->fetch()[0] === 'GUEST') {
        $_SESSION['is_guest'] = true;
    }
```

It's important now to understand when is set the `:id` as a `GUEST`. It is done in the post to `register`:

```
preg_match('/\A(ADMIN|USER|GUEST)--((?:###|\w)+)\z/i', $code, $matches);
    if (count($matches) === 3 && $app->code[$matches[1]] === $matches[2]) {
        $sth = $app->pdo->prepare('INSERT INTO acl (id, authorize) VALUES (:id, :authorize)');
        $sth->execute([':id' => $id, ':authorize' => $matches[1]]);
    } else {
        $sth = $app->pdo->prepare('INSERT INTO acl (id, authorize) VALUES (:id, "GUEST")');
        $sth->execute([':id' => $id]);
    }
```

Now we know what we have to exploit, but first let's take a look at `app->code`:

```
$app->code = [
    'ADMIN' => null, // TODO: Set code
    'USER' => null, // TODO: Set code
    'GUEST' => '###GUEST###'
];

```

So `$app->code[$matches[1]] === $matches[2]` has to become `null === null`.

How we can achieve it? Well it was quite challenging at first, because i tried multiple ideas but all of them failed.
In the end i remembered that we can try to break php on how he handles big strings as input.
So i decided to try with `CODE` equals to `"ADMIN--"+("_"*58845)`. Yes it was a overkill, but i just copy-pasted till i thought was enough to break it, and so we created a user.

After logging in we have the 2fa login. 

![Login 2FA](https://github.com/jbzteam/CTF/raw/master/CodeBlueCTF2017/login.jpg)

I used the google authenticator app to get the CODE needed to pass this authentication phase.

We are finally logged in and we can see that we have our button flag on the webpage. Clicking it we'll be redirected to the flag.

![Flag button](https://github.com/jbzteam/CTF/raw/master/CodeBlueCTF2017/flag.jpg)

The flag is: `CBCTF{pcR3_h45_b3En_rot73N_f0r_A_l0n6_7iM3:(}`.


