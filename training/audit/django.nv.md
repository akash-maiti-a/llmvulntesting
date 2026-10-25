# Label audit: django.nv (6 of 6 labelled alerts)
Mark each row: agree / disagree / unsure, comparing the label with the code.

## 1. taskManager/views.py:178 CWE-89 (semgrep sql-injection-db-cursor-execute)
label: **vulnerable** (entries ['dnv-sqli-upload'])
verdict: 

```
  154          else:
  155              if user.has_perm('can_change_group'):
  156                  return render_to_response(
  157                      'taskManager/manage_groups.html',
  158                      {
  159                          'users': user_list,
  160                          'logged_in': True},
  161                      RequestContext(request))
  162              else:
  163                  return redirect('/taskManager/', {'permission': False})
  164  
  165      return redirect('/taskManager/', {'logged_in': False})
  166  
  167  
  168  
  169  
  170  def upload(request, project_id):
  171  
  172      if request.method == 'POST':
  173  
  174          proj = Project.objects.get(pk=project_id)
  175          form = ProjectFileForm(request.POST, request.FILES)
  176  
  177          if form.is_valid():
  178>             name = request.POST.get('name', False)
  179              upload_path = store_uploaded_file(name, request.FILES['file'])
  180  
  181  
  182              curs = connection.cursor()
  183              curs.execute(
  184                  "insert into taskManager_file ('name','path','project_id') values ('%s','%s',%s)" %
  185                  (name, upload_path, project_id))
  186  
  187              # file = File(
  188              #name = name,
  189              #path = upload_path,
  190              # project = proj)
```

## 2. taskManager/views.py:387 CWE-601 (pysa pysa-5018)
label: **vulnerable** (entries ['dnv-redirect-logout'])
verdict: 

```
  363          proj.text = text
  364          proj.priority = project_priority
  365          proj.due_date = project_duedate
  366          proj.save()
  367  
  368          return redirect('/taskManager/' + project_id + '/')
  369      else:
  370          return render_to_response(
  371              'taskManager/project_edit.html', {'proj': proj}, RequestContext(request))
  372  
  373  
  374  
  375  
  376  def project_delete(request, project_id):
  377  
  378      project = Project.objects.get(pk=project_id)
  379      project.delete()
  380      return redirect('/taskManager/dashboard')
  381  
  382  
  383  
  384  
  385  def logout_view(request):
  386      logout(request)
  387>     return redirect(request.GET.get('redirect', '/taskManager/'))
  388  
  389  
  390  def login(request):
  391      if request.method == 'POST':
  392          username = request.POST.get('username', False)
  393          password = request.POST.get('password', False)
  394  
  395          if User.objects.filter(username=username).exists():
  396              user = authenticate(username=username, password=password)
  397              if user is not None:
  398                  if user.is_active:
  399                      auth_login(request, user)
```

## 3. taskManager/views.py:387 CWE-601 (semgrep py-taint-open-redirect)
label: **vulnerable** (entries ['dnv-redirect-logout'])
verdict: 

```
  363          proj.text = text
  364          proj.priority = project_priority
  365          proj.due_date = project_duedate
  366          proj.save()
  367  
  368          return redirect('/taskManager/' + project_id + '/')
  369      else:
  370          return render_to_response(
  371              'taskManager/project_edit.html', {'proj': proj}, RequestContext(request))
  372  
  373  
  374  
  375  
  376  def project_delete(request, project_id):
  377  
  378      project = Project.objects.get(pk=project_id)
  379      project.delete()
  380      return redirect('/taskManager/dashboard')
  381  
  382  
  383  
  384  
  385  def logout_view(request):
  386      logout(request)
  387>     return redirect(request.GET.get('redirect', '/taskManager/'))
  388  
  389  
  390  def login(request):
  391      if request.method == 'POST':
  392          username = request.POST.get('username', False)
  393          password = request.POST.get('password', False)
  394  
  395          if User.objects.filter(username=username).exists():
  396              user = authenticate(username=username, password=password)
  397              if user is not None:
  398                  if user.is_active:
  399                      auth_login(request, user)
```

## 4. taskManager/views.py:387 CWE-601 (semgrep open-redirect)
label: **vulnerable** (entries ['dnv-redirect-logout'])
verdict: 

```
  363          proj.text = text
  364          proj.priority = project_priority
  365          proj.due_date = project_duedate
  366          proj.save()
  367  
  368          return redirect('/taskManager/' + project_id + '/')
  369      else:
  370          return render_to_response(
  371              'taskManager/project_edit.html', {'proj': proj}, RequestContext(request))
  372  
  373  
  374  
  375  
  376  def project_delete(request, project_id):
  377  
  378      project = Project.objects.get(pk=project_id)
  379      project.delete()
  380      return redirect('/taskManager/dashboard')
  381  
  382  
  383  
  384  
  385  def logout_view(request):
  386      logout(request)
  387>     return redirect(request.GET.get('redirect', '/taskManager/'))
  388  
  389  
  390  def login(request):
  391      if request.method == 'POST':
  392          username = request.POST.get('username', False)
  393          password = request.POST.get('password', False)
  394  
  395          if User.objects.filter(username=username).exists():
  396              user = authenticate(username=username, password=password)
  397              if user is not None:
  398                  if user.is_active:
  399                      auth_login(request, user)
```

## 5. taskManager/views.py:185 CWE-89 (pysa pysa-5051)
label: **vulnerable** (entries ['dnv-sqli-upload'])
verdict: 

```
  161                      RequestContext(request))
  162              else:
  163                  return redirect('/taskManager/', {'permission': False})
  164  
  165      return redirect('/taskManager/', {'logged_in': False})
  166  
  167  
  168  
  169  
  170  def upload(request, project_id):
  171  
  172      if request.method == 'POST':
  173  
  174          proj = Project.objects.get(pk=project_id)
  175          form = ProjectFileForm(request.POST, request.FILES)
  176  
  177          if form.is_valid():
  178              name = request.POST.get('name', False)
  179              upload_path = store_uploaded_file(name, request.FILES['file'])
  180  
  181  
  182              curs = connection.cursor()
  183              curs.execute(
  184                  "insert into taskManager_file ('name','path','project_id') values ('%s','%s',%s)" %
  185>                 (name, upload_path, project_id))
  186  
  187              # file = File(
  188              #name = name,
  189              #path = upload_path,
  190              # project = proj)
  191  
  192              # file.save()
  193  
  194              return redirect('/taskManager/' + project_id +
  195                              '/', {'new_file_added': True})
  196          else:
  197              form = ProjectFileForm()
```

## 6. taskManager/views.py:184 CWE-89 (semgrep py-taint-sqli)
label: **vulnerable** (entries ['dnv-sqli-upload'])
verdict: 

```
  160                          'logged_in': True},
  161                      RequestContext(request))
  162              else:
  163                  return redirect('/taskManager/', {'permission': False})
  164  
  165      return redirect('/taskManager/', {'logged_in': False})
  166  
  167  
  168  
  169  
  170  def upload(request, project_id):
  171  
  172      if request.method == 'POST':
  173  
  174          proj = Project.objects.get(pk=project_id)
  175          form = ProjectFileForm(request.POST, request.FILES)
  176  
  177          if form.is_valid():
  178              name = request.POST.get('name', False)
  179              upload_path = store_uploaded_file(name, request.FILES['file'])
  180  
  181  
  182              curs = connection.cursor()
  183              curs.execute(
  184>                 "insert into taskManager_file ('name','path','project_id') values ('%s','%s',%s)" %
  185                  (name, upload_path, project_id))
  186  
  187              # file = File(
  188              #name = name,
  189              #path = upload_path,
  190              # project = proj)
  191  
  192              # file.save()
  193  
  194              return redirect('/taskManager/' + project_id +
  195                              '/', {'new_file_added': True})
  196          else:
```
