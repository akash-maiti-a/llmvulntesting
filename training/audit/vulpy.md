# Label audit: vulpy (4 of 4 labelled alerts)
Mark each row: agree / disagree / unsure, comparing the label with the code.

## 1. mod_user.py:80 CWE-89 (pysa pysa-5005)
label: **vulnerable** (entries ['vulpy-mod_user-12-89'])
verdict: 

```
   56          #session['username'] = libuser.login(username, password)
   57  
   58          #if session['username']:
   59  
   60  
   61      return render_template('user.create.html')
   62  
   63  
   64  @mod_user.route('/chpasswd', methods=['GET', 'POST'])
   65  def do_chpasswd():
   66  
   67      if request.method == 'POST':
   68  
   69          password = request.form.get('password')
   70          password_again = request.form.get('password_again')
   71  
   72          if password != password_again:
   73              flash("The passwords don't match")
   74              return render_template('user.chpasswd.html')
   75  
   76          if not libuser.password_complexity(password):
   77              flash("The password don't comply our complexity requirements")
   78              return render_template('user.chpasswd.html')
   79  
   80>         libuser.password_change(g.session['username'], password) # = libuser.login(username, password)
   81          flash("Password changed")
   82  
   83      return render_template('user.chpasswd.html')
   84  
   85  
```

## 2. mod_user.py:80 CWE-89 (pysa pysa-5051)
label: **vulnerable** (entries ['vulpy-mod_user-12-89'])
verdict: 

```
   56          #session['username'] = libuser.login(username, password)
   57  
   58          #if session['username']:
   59  
   60  
   61      return render_template('user.create.html')
   62  
   63  
   64  @mod_user.route('/chpasswd', methods=['GET', 'POST'])
   65  def do_chpasswd():
   66  
   67      if request.method == 'POST':
   68  
   69          password = request.form.get('password')
   70          password_again = request.form.get('password_again')
   71  
   72          if password != password_again:
   73              flash("The passwords don't match")
   74              return render_template('user.chpasswd.html')
   75  
   76          if not libuser.password_complexity(password):
   77              flash("The password don't comply our complexity requirements")
   78              return render_template('user.chpasswd.html')
   79  
   80>         libuser.password_change(g.session['username'], password) # = libuser.login(username, password)
   81          flash("Password changed")
   82  
   83      return render_template('user.chpasswd.html')
   84  
   85  
```

## 3. mod_user.py:52 CWE-89 (pysa pysa-5051)
label: **vulnerable** (entries ['vulpy-mod_user-4-89'])
verdict: 

```
   28                  flash("Invalid OTP");
   29                  return render_template('user.login.mfa.html')
   30  
   31          response = make_response(redirect('/'))
   32          response = libsession.create(response=response, username=username)
   33          return response
   34  
   35      return render_template('user.login.mfa.html')
   36  
   37  
   38  @mod_user.route('/create', methods=['GET', 'POST'])
   39  def do_create():
   40  
   41      session.pop('username', None)
   42  
   43      if request.method == 'POST':
   44  
   45          username = request.form.get('username')
   46          password = request.form.get('password')
   47          #email = request.form.get('password')
   48          if not username or not password:
   49              flash("Please, complete username and password")
   50              return render_template('user.create.html')
   51  
   52>         libuser.create(username, password)
   53          flash("User created. Please login.")
   54          return redirect('/user/login')
   55  
   56          #session['username'] = libuser.login(username, password)
   57  
   58          #if session['username']:
   59  
   60  
   61      return render_template('user.create.html')
   62  
   63  
   64  @mod_user.route('/chpasswd', methods=['GET', 'POST'])
```

## 4. mod_user.py:52 CWE-89 (pysa pysa-5005)
label: **vulnerable** (entries ['vulpy-mod_user-4-89'])
verdict: 

```
   28                  flash("Invalid OTP");
   29                  return render_template('user.login.mfa.html')
   30  
   31          response = make_response(redirect('/'))
   32          response = libsession.create(response=response, username=username)
   33          return response
   34  
   35      return render_template('user.login.mfa.html')
   36  
   37  
   38  @mod_user.route('/create', methods=['GET', 'POST'])
   39  def do_create():
   40  
   41      session.pop('username', None)
   42  
   43      if request.method == 'POST':
   44  
   45          username = request.form.get('username')
   46          password = request.form.get('password')
   47          #email = request.form.get('password')
   48          if not username or not password:
   49              flash("Please, complete username and password")
   50              return render_template('user.create.html')
   51  
   52>         libuser.create(username, password)
   53          flash("User created. Please login.")
   54          return redirect('/user/login')
   55  
   56          #session['username'] = libuser.login(username, password)
   57  
   58          #if session['username']:
   59  
   60  
   61      return render_template('user.create.html')
   62  
   63  
   64  @mod_user.route('/chpasswd', methods=['GET', 'POST'])
```
