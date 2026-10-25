# Label audit: benchmarkpython (30 of 386 labelled alerts)
Mark each row: agree / disagree / unsure, comparing the label with the code.

## 1. testcode/BenchmarkTest00259.py:42 CWE-601 (pysa pysa-5018)
label: **safe** (entries ['bp-00259'])
verdict: 

```
   18  from flask import redirect, url_for, request, make_response, render_template
   19  from helpers.utils import escape_for_html
   20  
   21  def init(app):
   22  
   23  	@app.route('/benchmark/redirect-00/BenchmarkTest00259', methods=['GET'])
   24  	def BenchmarkTest00259_get():
   25  		return BenchmarkTest00259_post()
   26  
   27  	@app.route('/benchmark/redirect-00/BenchmarkTest00259', methods=['POST'])
   28  	def BenchmarkTest00259_post():
   29  		RESPONSE = ""
   30  
   31  		values = request.form.getlist("BenchmarkTest00259")
   32  		param = ""
   33  		if values:
   34  			param = values[0]
   35  
   36  		num = 106
   37  		
   38  		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
   39  
   40  		import flask
   41  
   42> 		return flask.redirect(bar)
   43  
   44  		return RESPONSE
   45  
   46  
```

## 2. testcode/BenchmarkTest00353.py:48 CWE-22 (pysa pysa-5011)
label: **vulnerable** (entries ['bp-00353'])
verdict: 

```
   24  	def BenchmarkTest00353_get():
   25  		return BenchmarkTest00353_post()
   26  
   27  	@app.route('/benchmark/pathtraver-00/BenchmarkTest00353', methods=['POST'])
   28  	def BenchmarkTest00353_post():
   29  		RESPONSE = ""
   30  
   31  		param = ""
   32  		for name in request.form.keys():
   33  			if "BenchmarkTest00353" in request.form.getlist(name):
   34  				param = name
   35  				break
   36  
   37  		import base64
   38  		tmp = base64.b64encode(param.encode('utf-8'))
   39  		bar = base64.b64decode(tmp).decode('utf-8')
   40  
   41  		import helpers.utils
   42  
   43  		fileName = None
   44  		fd = None
   45  
   46  		try:
   47  			fileName = f'{helpers.utils.TESTFILES_DIR}/{bar}'
   48> 			fd = open(fileName, 'rb')
   49  			RESPONSE += (
   50  				f'The beginning of file: \'{escape_for_html(fileName)}\' is:\n\n'
   51  				f'{escape_for_html(fd.read(1000).decode('utf-8'))}'
   52  			)
   53  		except IOError as e:
   54  			RESPONSE += (
   55  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   56  				f'{escape_for_html(e.strerror)}'
   57  			)
   58  		finally:
   59  			try:
   60  				if fd is not None:
```

## 3. testcode/BenchmarkTest00319.py:56 CWE-327 (semgrep insecure-hash-function)
label: **vulnerable** (entries ['bp-00319'])
verdict: 

```
   32  		
   33  		wrapped = helpers.separate_request.request_wrapper(request)
   34  		param = wrapped.get_form_parameter("BenchmarkTest00319")
   35  		if not param:
   36  			param = ""
   37  
   38  		import helpers.utils
   39  		bar = helpers.utils.escape_for_html(param)
   40  
   41  		import hashlib, base64
   42  		import io, helpers.utils
   43  
   44  		input = ''
   45  		if isinstance(bar, str):
   46  			input = bar.encode('utf-8')
   47  		elif isinstance(bar, io.IOBase):
   48  			input = bar.read(1000)
   49  
   50  		if len(input) == 0:
   51  			RESPONSE += (
   52  				'Cannot generate hash: Input was empty.'
   53  			)
   54  			return RESPONSE
   55  
   56> 		hash = hashlib.new('md5')
   57  		hash.update(input)
   58  
   59  		result = hash.digest()
   60  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   61  		f.write(f'hash_value={base64.b64encode(result)}\n')
   62  		RESPONSE += (
   63  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   64  		)
   65  		f.close()
   66  
   67  		return RESPONSE
   68  
```

## 4. testcode/BenchmarkTest00818.py:48 CWE-95 (semgrep py-taint-code-injection)
label: **safe** (entries ['bp-00818'])
verdict: 

```
   24  	def BenchmarkTest00818_get():
   25  		return BenchmarkTest00818_post()
   26  
   27  	@app.route('/benchmark/codeinj-00/BenchmarkTest00818', methods=['POST'])
   28  	def BenchmarkTest00818_post():
   29  		RESPONSE = ""
   30  
   31  		values = request.args.getlist("BenchmarkTest00818")
   32  		param = ""
   33  		if values:
   34  			param = values[0]
   35  
   36  		import helpers.ThingFactory
   37  		
   38  		thing = helpers.ThingFactory.createThing()
   39  		bar = thing.doSomething(param)
   40  
   41  		if not bar.startswith('\'') or not bar.endswith('\'') or '\'' in bar[1:-1]:
   42  			RESPONSE += (
   43  				"Eval argument must be a plain string literal."
   44  			)
   45  			return RESPONSE		
   46  
   47  		try:
   48> 			RESPONSE += (
   49  				eval(bar)
   50  			)
   51  		except:
   52  			RESPONSE += (
   53  				f'Error evaluating expression \'{escape_for_html(bar)}\''
   54  			)
   55  
   56  		return RESPONSE
   57  
   58  
```

## 5. testcode/BenchmarkTest00526.py:50 CWE-22 (pysa pysa-5011)
label: **vulnerable** (entries ['bp-00526'])
verdict: 

```
   26  
   27  	@app.route('/benchmark/pathtraver-00/BenchmarkTest00526', methods=['POST'])
   28  	def BenchmarkTest00526_post():
   29  		RESPONSE = ""
   30  
   31  		param = ""
   32  		headers = request.headers.getlist("BenchmarkTest00526")
   33  		
   34  		if headers:
   35  			param = headers[0]
   36  
   37  		import helpers.ThingFactory
   38  		
   39  		thing = helpers.ThingFactory.createThing()
   40  		bar = thing.doSomething(param)
   41  
   42  		import pathlib
   43  		import helpers.utils
   44  
   45  		try:
   46  			testfiles = pathlib.Path(helpers.utils.TESTFILES_DIR)
   47  			p = testfiles / bar
   48  			RESPONSE += (
   49  				f'The beginning of file: \'{escape_for_html(str(p))}\' is:\n\n'
   50> 				f'{escape_for_html(p.read_text()[:1000])}'
   51  			)
   52  		except OSError:
   53  			RESPONSE += (
   54  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   55  				f'{escape_for_html(e.strerror)}'
   56  			)
   57  
   58  		return RESPONSE
   59  
   60  
```

## 6. testcode/BenchmarkTest00510.py:46 CWE-502 (pysa pysa-6066)
label: **vulnerable** (entries ['bp-00510'])
verdict: 

```
   22  
   23  	@app.route('/benchmark/deserialization-00/BenchmarkTest00510', methods=['GET'])
   24  	def BenchmarkTest00510_get():
   25  		return BenchmarkTest00510_post()
   26  
   27  	@app.route('/benchmark/deserialization-00/BenchmarkTest00510', methods=['POST'])
   28  	def BenchmarkTest00510_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.headers.get("BenchmarkTest00510")
   32  		if not param:
   33  		    param = ""
   34  
   35  		num = 106
   36  		
   37  		bar = "This should never happen" if (7*42) - num > 200 else param
   38  
   39  		import pickle
   40  		import base64
   41  		import helpers.utils
   42  
   43  		helpers.utils.sharedstr = "no pickles to be seen here"
   44  
   45  		try:
   46> 			unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
   47  		except:
   48  			RESPONSE += (
   49  				'Unpickling failed!'
   50  			)
   51  			return RESPONSE
   52  
   53  		RESPONSE += (
   54  			f'shared string is {helpers.utils.sharedstr}'
   55  		)
   56  
   57  		return RESPONSE
   58  
```

## 7. testcode/BenchmarkTest00284.py:44 CWE-89 (pysa pysa-5051)
label: **vulnerable** (entries ['bp-00284'])
verdict: 

```
   20  
   21  def init(app):
   22  
   23  	@app.route('/benchmark/sqli-00/BenchmarkTest00284', methods=['GET'])
   24  	def BenchmarkTest00284_get():
   25  		return BenchmarkTest00284_post()
   26  
   27  	@app.route('/benchmark/sqli-00/BenchmarkTest00284', methods=['POST'])
   28  	def BenchmarkTest00284_post():
   29  		RESPONSE = ""
   30  
   31  		import helpers.separate_request
   32  		
   33  		wrapped = helpers.separate_request.request_wrapper(request)
   34  		param = wrapped.get_form_parameter("BenchmarkTest00284")
   35  		if not param:
   36  			param = ""
   37  
   38  		bar = "This should never happen"
   39  		if 'should' in bar:
   40  			bar = param
   41  
   42  		import helpers.db_sqlite
   43  
   44> 		sql = f'SELECT username from USERS where password = \'{bar}\''
   45  		con = helpers.db_sqlite.get_connection()
   46  		cur = con.cursor()
   47  		cur.execute(sql)
   48  		RESPONSE += (
   49  			helpers.db_sqlite.results(cur, sql)
   50  		)
   51  		con.close()
   52  
   53  		return RESPONSE
   54  
   55  
```

## 8. testcode/BenchmarkTest00067.py:47 CWE-601 (pysa pysa-5018)
label: **vulnerable** (entries ['bp-00067'])
verdict: 

```
   23  	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
   24  	def BenchmarkTest00067_get():
   25  		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
   26  		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
   27  			max_age=60*3,
   28  			secure=True,
   29  			path=request.path,
   30  			domain='localhost')
   31  		return response
   32  		return BenchmarkTest00067_post()
   33  
   34  	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
   35  	def BenchmarkTest00067_post():
   36  		RESPONSE = ""
   37  
   38  		import urllib.parse
   39  		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
   40  
   41  		import base64
   42  		tmp = base64.b64encode(param.encode('utf-8'))
   43  		bar = base64.b64decode(tmp).decode('utf-8')
   44  
   45  		import flask
   46  
   47> 		return flask.redirect(bar)
   48  
   49  		return RESPONSE
   50  
   51  
```

## 9. testcode/BenchmarkTest00503.py:41 CWE-95 (pysa pysa-5001)
label: **vulnerable** (entries ['bp-00503'])
verdict: 

```
   17  
   18  from flask import redirect, url_for, request, make_response, render_template
   19  from helpers.utils import escape_for_html
   20  
   21  def init(app):
   22  
   23  	@app.route('/benchmark/codeinj-00/BenchmarkTest00503', methods=['GET'])
   24  	def BenchmarkTest00503_get():
   25  		return BenchmarkTest00503_post()
   26  
   27  	@app.route('/benchmark/codeinj-00/BenchmarkTest00503', methods=['POST'])
   28  	def BenchmarkTest00503_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.headers.get("BenchmarkTest00503")
   32  		if not param:
   33  		    param = ""
   34  
   35  		import base64
   36  		tmp = base64.b64encode(param.encode('utf-8'))
   37  		bar = base64.b64decode(tmp).decode('utf-8')
   38  
   39  		try:
   40  			RESPONSE += (
   41> 				eval(bar)
   42  			)
   43  		except:
   44  			RESPONSE += (
   45  				f'Error evaluating expression \'{escape_for_html(bar)}\''
   46  			)
   47  
   48  		return RESPONSE
   49  
   50  
```

## 10. testcode/BenchmarkTest00174.py:50 CWE-22 (pysa pysa-5011)
label: **safe** (entries ['bp-00174'])
verdict: 

```
   26  
   27  	@app.route('/benchmark/pathtraver-00/BenchmarkTest00174', methods=['POST'])
   28  	def BenchmarkTest00174_post():
   29  		RESPONSE = ""
   30  
   31  		values = request.form.getlist("BenchmarkTest00174")
   32  		param = ""
   33  		if values:
   34  			param = values[0]
   35  
   36  		num = 86
   37  		
   38  		if 7 * 42 - num > 200:
   39  			bar = 'This_should_always_happen'
   40  		else:
   41  			bar = param
   42  
   43  		import helpers.utils
   44  
   45  		fileName = None
   46  		fd = None
   47  
   48  		try:
   49  			fileName = f'{helpers.utils.TESTFILES_DIR}/{bar}'
   50> 			fd = open(fileName, 'rb')
   51  			RESPONSE += (
   52  				f'The beginning of file: \'{escape_for_html(fileName)}\' is:\n\n'
   53  				f'{escape_for_html(fd.read(1000).decode('utf-8'))}'
   54  			)
   55  		except IOError as e:
   56  			RESPONSE += (
   57  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   58  				f'{escape_for_html(e.strerror)}'
   59  			)
   60  		finally:
   61  			try:
   62  				if fd is not None:
```

## 11. testcode/BenchmarkTest00728.py:50 CWE-95 (pysa pysa-5001)
label: **vulnerable** (entries ['bp-00728'])
verdict: 

```
   26  
   27  	@app.route('/benchmark/codeinj-00/BenchmarkTest00728', methods=['POST'])
   28  	def BenchmarkTest00728_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.args.get("BenchmarkTest00728")
   32  		if not param:
   33  			param = ""
   34  
   35  		possible = "ABC"
   36  		guess = possible[0]
   37  		
   38  		match guess:
   39  			case 'A':
   40  				bar = param
   41  			case 'B':
   42  				bar = 'bob'
   43  			case 'C' | 'D':
   44  				bar = param
   45  			case _:
   46  				bar = 'bob\'s your uncle'
   47  
   48  		try:
   49  			RESPONSE += (
   50> 				eval(bar)
   51  			)
   52  		except:
   53  			RESPONSE += (
   54  				f'Error evaluating expression \'{escape_for_html(bar)}\''
   55  			)
   56  
   57  		return RESPONSE
   58  
   59  
```

## 12. testcode/BenchmarkTest00442.py:51 CWE-22 (semgrep py-taint-path-traversal)
label: **safe** (entries ['bp-00442'])
verdict: 

```
   27  	@app.route('/benchmark/pathtraver-00/BenchmarkTest00442', methods=['POST'])
   28  	def BenchmarkTest00442_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.headers.get("BenchmarkTest00442")
   32  		if not param:
   33  		    param = ""
   34  
   35  		TestParam = "This should never happen"
   36  		if 'should' not in TestParam:
   37  			bar = "Ifnot case passed"
   38  		else:
   39  			bar = param
   40  
   41  		import helpers.utils
   42  
   43  		if '../' in bar:
   44  			RESPONSE += (
   45  				'File name must not contain \'../\''
   46  			)
   47  			return RESPONSE
   48  
   49  		try:
   50  			fileName = f'{helpers.utils.TESTFILES_DIR}/{bar}'
   51> 			fd = open(fileName, 'wb')
   52  			RESPONSE += (
   53  				f'Now ready to write to file: {escape_for_html(fileName)}'
   54  			)
   55  		except IOError as e:
   56  			RESPONSE += (
   57  				f'Problem reading from file \'{escape_for_html(fileName)}\': '
   58  				f'{escape_for_html(e.strerror)}'
   59  			)
   60  		finally:
   61  			try:
   62  				if fd is not None:
   63  					fd.close()
```

## 13. testcode/BenchmarkTest00525.py:49 CWE-22 (pysa pysa-5011)
label: **safe** (entries ['bp-00525'])
verdict: 

```
   25  		return BenchmarkTest00525_post()
   26  
   27  	@app.route('/benchmark/pathtraver-00/BenchmarkTest00525', methods=['POST'])
   28  	def BenchmarkTest00525_post():
   29  		RESPONSE = ""
   30  
   31  		param = ""
   32  		headers = request.headers.getlist("BenchmarkTest00525")
   33  		
   34  		if headers:
   35  			param = headers[0]
   36  
   37  		num = 86
   38  		
   39  		if 7 * 42 - num > 200:
   40  			bar = 'This_should_always_happen'
   41  		else:
   42  			bar = param
   43  
   44  		import pathlib
   45  		import helpers.utils
   46  
   47  		try:
   48  			testfiles = pathlib.Path(helpers.utils.TESTFILES_DIR)
   49> 			p = testfiles / bar
   50  			RESPONSE += (
   51  				f'The beginning of file: \'{escape_for_html(str(p))}\' is:\n\n'
   52  				f'{escape_for_html(p.read_text()[:1000])}'
   53  			)
   54  		except OSError:
   55  			RESPONSE += (
   56  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   57  				f'{escape_for_html(e.strerror)}'
   58  			)
   59  
   60  		return RESPONSE
   61  
```

## 14. testcode/BenchmarkTest01077.py:55 CWE-327 (semgrep insecure-hash-algorithm-md5)
label: **vulnerable** (entries ['bp-01077'])
verdict: 

```
   31  		parts = request.path.split("/")
   32  		param = parts[1]
   33  		if not param:
   34  			param = ""
   35  
   36  		import html
   37  		
   38  		bar = html.escape(param)
   39  
   40  		import hashlib, base64
   41  		import io, helpers.utils
   42  
   43  		input = ''
   44  		if isinstance(bar, str):
   45  			input = bar.encode('utf-8')
   46  		elif isinstance(bar, io.IOBase):
   47  			input = bar.read(1000)
   48  
   49  		if len(input) == 0:
   50  			RESPONSE += (
   51  				'Cannot generate hash: Input was empty.'
   52  			)
   53  			return RESPONSE
   54  
   55> 		hash = hashlib.md5()
   56  		hash.update(input)
   57  
   58  		result = hash.digest()
   59  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   60  		f.write(f'hash_value={base64.b64encode(result)}\n')
   61  		RESPONSE += (
   62  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   63  		)
   64  		f.close()
   65  
   66  		return RESPONSE
   67  
```

## 15. testcode/BenchmarkTest01202.py:49 CWE-22 (semgrep py-taint-path-traversal)
label: **safe** (entries ['bp-01202'])
verdict: 

```
   25  		return BenchmarkTest01202_post()
   26  
   27  	@app.route('/benchmark/pathtraver-02/BenchmarkTest01202', methods=['POST'])
   28  	def BenchmarkTest01202_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.args.get("BenchmarkTest01202")
   32  		if not param:
   33  			param = ""
   34  
   35  
   36  		import helpers.utils
   37  
   38  		fileName = None
   39  		fd = None
   40  
   41  		if '../' in param:
   42  			RESPONSE += (
   43  				'File name must not include \'../\''
   44  			)
   45  			return RESPONSE
   46  
   47  		try:
   48  			fileName = f'{helpers.utils.TESTFILES_DIR}/{param}'
   49> 			fd = open(fileName, 'rb')
   50  			RESPONSE += (
   51  				f'The beginning of file: \'{escape_for_html(fileName)}\' is:\n\n'
   52  				f'{escape_for_html(fd.read(1000).decode('utf-8'))}'
   53  			)
   54  		except IOError as e:
   55  			RESPONSE += (
   56  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   57  				f'{escape_for_html(e.strerror)}'
   58  			)
   59  		finally:
   60  			try:
   61  				if fd is not None:
```

## 16. testcode/BenchmarkTest00708.py:63 CWE-327 (semgrep insecure-hash-function)
label: **vulnerable** (entries ['bp-00708'])
verdict: 

```
   39  			case 'A':
   40  				bar = param
   41  			case 'B':
   42  				bar = 'bob'
   43  			case 'C' | 'D':
   44  				bar = param
   45  			case _:
   46  				bar = 'bob\'s your uncle'
   47  
   48  		import hashlib, base64
   49  		import io, helpers.utils
   50  
   51  		input = ''
   52  		if isinstance(bar, str):
   53  			input = bar.encode('utf-8')
   54  		elif isinstance(bar, io.IOBase):
   55  			input = bar.read(1000)
   56  
   57  		if len(input) == 0:
   58  			RESPONSE += (
   59  				'Cannot generate hash: Input was empty.'
   60  			)
   61  			return RESPONSE
   62  
   63> 		hash = hashlib.new('md5')
   64  		hash.update(input)
   65  
   66  		result = hash.digest()
   67  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   68  		f.write(f'hash_value={base64.b64encode(result)}\n')
   69  		RESPONSE += (
   70  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   71  		)
   72  		f.close()
   73  
   74  		return RESPONSE
   75  
```

## 17. testcode/BenchmarkTest00818.py:49 CWE-95 (pysa pysa-5001)
label: **safe** (entries ['bp-00818'])
verdict: 

```
   25  		return BenchmarkTest00818_post()
   26  
   27  	@app.route('/benchmark/codeinj-00/BenchmarkTest00818', methods=['POST'])
   28  	def BenchmarkTest00818_post():
   29  		RESPONSE = ""
   30  
   31  		values = request.args.getlist("BenchmarkTest00818")
   32  		param = ""
   33  		if values:
   34  			param = values[0]
   35  
   36  		import helpers.ThingFactory
   37  		
   38  		thing = helpers.ThingFactory.createThing()
   39  		bar = thing.doSomething(param)
   40  
   41  		if not bar.startswith('\'') or not bar.endswith('\'') or '\'' in bar[1:-1]:
   42  			RESPONSE += (
   43  				"Eval argument must be a plain string literal."
   44  			)
   45  			return RESPONSE		
   46  
   47  		try:
   48  			RESPONSE += (
   49> 				eval(bar)
   50  			)
   51  		except:
   52  			RESPONSE += (
   53  				f'Error evaluating expression \'{escape_for_html(bar)}\''
   54  			)
   55  
   56  		return RESPONSE
   57  
   58  
```

## 18. testcode/BenchmarkTest00735.py:46 CWE-502 (semgrep py-taint-deserialization)
label: **vulnerable** (entries ['bp-00735'])
verdict: 

```
   22  
   23  	@app.route('/benchmark/deserialization-00/BenchmarkTest00735', methods=['GET'])
   24  	def BenchmarkTest00735_get():
   25  		return BenchmarkTest00735_post()
   26  
   27  	@app.route('/benchmark/deserialization-00/BenchmarkTest00735', methods=['POST'])
   28  	def BenchmarkTest00735_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.args.get("BenchmarkTest00735")
   32  		if not param:
   33  			param = ""
   34  
   35  		import markupsafe
   36  		
   37  		bar = markupsafe.escape(param)
   38  
   39  		import pickle
   40  		import base64
   41  		import helpers.utils
   42  
   43  		helpers.utils.sharedstr = "no pickles to be seen here"
   44  
   45  		try:
   46> 			unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
   47  		except:
   48  			RESPONSE += (
   49  				'Unpickling failed!'
   50  			)
   51  			return RESPONSE
   52  
   53  		RESPONSE += (
   54  			f'shared string is {helpers.utils.sharedstr}'
   55  		)
   56  
   57  		return RESPONSE
   58  
```

## 19. testcode/BenchmarkTest00597.py:48 CWE-601 (pysa pysa-5018)
label: **safe** (entries ['bp-00597'])
verdict: 

```
   24  	def BenchmarkTest00597_get():
   25  		return BenchmarkTest00597_post()
   26  
   27  	@app.route('/benchmark/redirect-00/BenchmarkTest00597', methods=['POST'])
   28  	def BenchmarkTest00597_post():
   29  		RESPONSE = ""
   30  
   31  		param = ""
   32  		headers = request.headers.getlist("BenchmarkTest00597")
   33  		
   34  		if headers:
   35  			param = headers[0]
   36  
   37  		bar = "alsoconst"
   38  		if param:
   39  			lst = []
   40  			lst.append('const')
   41  			lst.append(param)
   42  			lst.append('moreconst')
   43  			lst.pop(0)
   44  			bar = lst[1]
   45  
   46  		import flask
   47  
   48> 		return flask.redirect(bar)
   49  
   50  		return RESPONSE
   51  
   52  
```

## 20. testcode/BenchmarkTest01083.py:45 CWE-79 (pysa pysa-5008)
label: **safe** (entries ['bp-01083'])
verdict: 

```
   21  def init(app):
   22  
   23  	@app.route('/benchmark/xss-00/BenchmarkTest01083', methods=['GET'])
   24  	def BenchmarkTest01083_get():
   25  		return BenchmarkTest01083_post()
   26  
   27  	@app.route('/benchmark/xss-00/BenchmarkTest01083', methods=['POST'])
   28  	def BenchmarkTest01083_post():
   29  		RESPONSE = ""
   30  
   31  		parts = request.path.split("/")
   32  		param = parts[1]
   33  		if not param:
   34  			param = ""
   35  
   36  		bar = ''
   37  		if param:
   38  			bar = param.split(' ')[0]
   39  
   40  
   41  		RESPONSE += (
   42  			'The value of the bar parameter is now in a custom header.'
   43  		)
   44  
   45> 		RESPONSE = make_response((RESPONSE, {'yourBenchmarkTest01083': bar}))
   46  		
   47  
   48  		return RESPONSE
   49  
   50  
```

## 21. testcode/BenchmarkTest00748.py:45 CWE-22 (pysa pysa-5011)
label: **safe** (entries ['bp-00748'])
verdict: 

```
   21  def init(app):
   22  
   23  	@app.route('/benchmark/pathtraver-01/BenchmarkTest00748', methods=['GET'])
   24  	def BenchmarkTest00748_get():
   25  		return BenchmarkTest00748_post()
   26  
   27  	@app.route('/benchmark/pathtraver-01/BenchmarkTest00748', methods=['POST'])
   28  	def BenchmarkTest00748_post():
   29  		RESPONSE = ""
   30  
   31  		values = request.args.getlist("BenchmarkTest00748")
   32  		param = ""
   33  		if values:
   34  			param = values[0]
   35  
   36  		num = 106
   37  		
   38  		bar = "This should never happen" if (7*42) - num > 200 else param
   39  
   40  		import pathlib
   41  		import helpers.utils
   42  
   43  		try:
   44  			testfiles = pathlib.Path(helpers.utils.TESTFILES_DIR)
   45> 			p = (testfiles / bar).resolve()
   46  
   47  			if not str(p).startswith(str(testfiles)):
   48  				RESPONSE += (
   49  					"Invalid Path."
   50  				)
   51  				return RESPONSE
   52  
   53  			RESPONSE += (
   54  				f'The beginning of file: \'{escape_for_html(str(p))}\' is:\n\n'
   55  				f'{escape_for_html(p.read_text()[:1000])}'
   56  			)
   57  		except OSError:
```

## 22. testcode/BenchmarkTest01145.py:53 CWE-327 (semgrep insecure-hash-function)
label: **vulnerable** (entries ['bp-01145'])
verdict: 

```
   29  		RESPONSE = ""
   30  
   31  		import helpers.separate_request
   32  		scr = helpers.separate_request.request_wrapper(request)
   33  		param = scr.get_safe_value("BenchmarkTest01145")
   34  
   35  		import helpers.utils
   36  		bar = helpers.utils.escape_for_html(param)
   37  
   38  		import hashlib, base64
   39  		import io, helpers.utils
   40  
   41  		input = ''
   42  		if isinstance(bar, str):
   43  			input = bar.encode('utf-8')
   44  		elif isinstance(bar, io.IOBase):
   45  			input = bar.read(1000)
   46  
   47  		if len(input) == 0:
   48  			RESPONSE += (
   49  				'Cannot generate hash: Input was empty.'
   50  			)
   51  			return RESPONSE
   52  
   53> 		hash = hashlib.new('md5')
   54  		hash.update(input)
   55  
   56  		result = hash.digest()
   57  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   58  		f.write(f'hash_value={base64.b64encode(result)}\n')
   59  		RESPONSE += (
   60  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   61  		)
   62  		f.close()
   63  
   64  		return RESPONSE
   65  
```

## 23. testcode/BenchmarkTest00078.py:53 CWE-502 (pysa pysa-6066)
label: **vulnerable** (entries ['bp-00078'])
verdict: 

```
   29  			path=request.path,
   30  			domain='localhost')
   31  		return response
   32  		return BenchmarkTest00078_post()
   33  
   34  	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
   35  	def BenchmarkTest00078_post():
   36  		RESPONSE = ""
   37  
   38  		import urllib.parse
   39  		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00078", "noCookieValueSupplied"))
   40  
   41  		string9895 = 'help'
   42  		string9895 += param
   43  		string9895 += 'snapes on a plane'
   44  		bar = string9895[4:-17]
   45  
   46  		import pickle
   47  		import base64
   48  		import helpers.utils
   49  
   50  		helpers.utils.sharedstr = "no pickles to be seen here"
   51  
   52  		try:
   53> 			unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
   54  		except:
   55  			RESPONSE += (
   56  				'Unpickling failed!'
   57  			)
   58  			return RESPONSE
   59  
   60  		RESPONSE += (
   61  			f'shared string is {helpers.utils.sharedstr}'
   62  		)
   63  
   64  		return RESPONSE
   65  
```

## 24. testcode/BenchmarkTest00713.py:58 CWE-327 (semgrep insecure-hash-algorithm-md5)
label: **vulnerable** (entries ['bp-00713'])
verdict: 

```
   34  
   35  		string97260 = ''
   36  		data12 = ''
   37  		copy = string97260
   38  		string97260 = ''
   39  		string97260 += param
   40  		copy += 'SomeOKString'
   41  		bar = copy
   42  
   43  		import hashlib, base64
   44  		import io, helpers.utils
   45  
   46  		input = ''
   47  		if isinstance(bar, str):
   48  			input = bar.encode('utf-8')
   49  		elif isinstance(bar, io.IOBase):
   50  			input = bar.read(1000)
   51  
   52  		if len(input) == 0:
   53  			RESPONSE += (
   54  				'Cannot generate hash: Input was empty.'
   55  			)
   56  			return RESPONSE
   57  
   58> 		hash = hashlib.md5()
   59  		hash.update(input)
   60  
   61  		result = hash.digest()
   62  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   63  		f.write(f'hash_value={base64.b64encode(result)}\n')
   64  		RESPONSE += (
   65  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   66  		)
   67  		f.close()
   68  
   69  		return RESPONSE
   70  
```

## 25. testcode/BenchmarkTest01192.py:46 CWE-22 (pysa pysa-5011)
label: **vulnerable** (entries ['bp-01192'])
verdict: 

```
   22  
   23  	@app.route('/benchmark/pathtraver-02/BenchmarkTest01192', methods=['GET'])
   24  	def BenchmarkTest01192_get():
   25  		return BenchmarkTest01192_post()
   26  
   27  	@app.route('/benchmark/pathtraver-02/BenchmarkTest01192', methods=['POST'])
   28  	def BenchmarkTest01192_post():
   29  		RESPONSE = ""
   30  
   31  		param = ""
   32  		for name in request.form.keys():
   33  			if "BenchmarkTest01192" in request.form.getlist(name):
   34  				param = name
   35  				break
   36  
   37  
   38  		import pathlib
   39  		import helpers.utils
   40  
   41  		try:
   42  			testfiles = pathlib.Path(helpers.utils.TESTFILES_DIR)
   43  			p = testfiles / param
   44  			RESPONSE += (
   45  				f'The beginning of file: \'{escape_for_html(str(p))}\' is:\n\n'
   46> 				f'{escape_for_html(p.read_text()[:1000])}'
   47  			)
   48  		except OSError:
   49  			RESPONSE += (
   50  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   51  				f'{escape_for_html(e.strerror)}'
   52  			)
   53  
   54  		return RESPONSE
   55  
   56  
   57  
```

## 26. testcode/BenchmarkTest00580.py:56 CWE-327 (semgrep insecure-hash-function)
label: **vulnerable** (entries ['bp-00580'])
verdict: 

```
   32  		headers = request.headers.getlist("BenchmarkTest00580")
   33  		
   34  		if headers:
   35  			param = headers[0]
   36  
   37  		bar = ''
   38  		if param:
   39  			bar = param.split(' ')[0]
   40  
   41  		import hashlib, base64
   42  		import io, helpers.utils
   43  
   44  		input = ''
   45  		if isinstance(bar, str):
   46  			input = bar.encode('utf-8')
   47  		elif isinstance(bar, io.IOBase):
   48  			input = bar.read(1000)
   49  
   50  		if len(input) == 0:
   51  			RESPONSE += (
   52  				'Cannot generate hash: Input was empty.'
   53  			)
   54  			return RESPONSE
   55  
   56> 		hash = hashlib.new('md5')
   57  		hash.update(input)
   58  
   59  		result = hash.digest()
   60  		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
   61  		f.write(f'hash_value={base64.b64encode(result)}\n')
   62  		RESPONSE += (
   63  			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
   64  		)
   65  		f.close()
   66  
   67  		return RESPONSE
   68  
```

## 27. testcode/BenchmarkTest00992.py:55 CWE-502 (pysa pysa-6066)
label: **vulnerable** (entries ['bp-00992'])
verdict: 

```
   31  		import urllib.parse
   32  		
   33  		query_string = request.query_string.decode('utf-8')
   34  		paramLoc = query_string.find("BenchmarkTest00992" + '=')
   35  		if paramLoc == -1:
   36  			return f"request.query_string did not contain expected parameter \'{"BenchmarkTest00992"}\'."
   37  		param = query_string[paramLoc + len("BenchmarkTest00992") + 1:]
   38  		ampLoc = param.find('&')
   39  		if ampLoc != -1:
   40  			param = param[:ampLoc]
   41  		
   42  		param = urllib.parse.unquote_plus(param)
   43  
   44  		import html
   45  		
   46  		bar = html.escape(param)
   47  
   48  		import pickle
   49  		import base64
   50  		import helpers.utils
   51  
   52  		helpers.utils.sharedstr = "no pickles to be seen here"
   53  
   54  		try:
   55> 			unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
   56  		except:
   57  			RESPONSE += (
   58  				'Unpickling failed!'
   59  			)
   60  			return RESPONSE
   61  
   62  		RESPONSE += (
   63  			f'shared string is {helpers.utils.sharedstr}'
   64  		)
   65  
   66  		return RESPONSE
   67  
```

## 28. testcode/BenchmarkTest00094.py:54 CWE-22 (pysa pysa-5011)
label: **safe** (entries ['bp-00094'])
verdict: 

```
   30  
   31  		param = request.form.get("BenchmarkTest00094")
   32  		if not param:
   33  			param = ""
   34  
   35  		num = 106
   36  		
   37  		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
   38  
   39  		import pathlib
   40  		import helpers.utils
   41  
   42  		try:
   43  			testfiles = pathlib.Path(helpers.utils.TESTFILES_DIR)
   44  			p = (testfiles / bar).resolve()
   45  
   46  			if not str(p).startswith(str(testfiles)):
   47  				RESPONSE += (
   48  					"Invalid Path."
   49  				)
   50  				return RESPONSE
   51  
   52  			RESPONSE += (
   53  				f'The beginning of file: \'{escape_for_html(str(p))}\' is:\n\n'
   54> 				f'{escape_for_html(p.read_text()[:1000])}'
   55  			)
   56  		except OSError:
   57  			RESPONSE += (
   58  				f'Problem reading from file \'{{escape_for_html(fileName)}}\': '
   59  				f'{escape_for_html(e.strerror)}'
   60  			)
   61  
   62  		return RESPONSE
   63  
   64  
```

## 29. testcode/BenchmarkTest00462.py:48 CWE-611 (pysa pysa-5007)
label: **vulnerable** (entries ['bp-00462'])
verdict: 

```
   24  	def BenchmarkTest00462_get():
   25  		return BenchmarkTest00462_post()
   26  
   27  	@app.route('/benchmark/xxe-00/BenchmarkTest00462', methods=['POST'])
   28  	def BenchmarkTest00462_post():
   29  		RESPONSE = ""
   30  
   31  		param = request.headers.get("BenchmarkTest00462")
   32  		if not param:
   33  		    param = ""
   34  
   35  		import helpers.ThingFactory
   36  		
   37  		thing = helpers.ThingFactory.createThing()
   38  		bar = thing.doSomething(param)
   39  
   40  		import xml.dom.minidom
   41  		import xml.sax.handler
   42  
   43  		try:
   44  			parser = xml.sax.make_parser()
   45  			# all features are disabled by default
   46  			parser.setFeature(xml.sax.handler.feature_external_ges, True)
   47  
   48> 			doc = xml.dom.minidom.parseString(bar, parser)
   49  
   50  			out = ''
   51  			processing = [doc.documentElement]
   52  			while processing:
   53  				e = processing.pop(0)
   54  				if e.nodeType == xml.dom.Node.TEXT_NODE:
   55  					out += e.data
   56  				else:
   57  					processing[:0] = e.childNodes
   58  
   59  			RESPONSE += (
   60  				f'Your XML doc results are: <br>{escape_for_html(out)}'
```

## 30. testcode/BenchmarkTest00620.py:50 CWE-22 (pysa pysa-5011)
label: **vulnerable** (entries ['bp-00620'])
verdict: 

```
   26  
   27  	@app.route('/benchmark/pathtraver-01/BenchmarkTest00620', methods=['POST'])
   28  	def BenchmarkTest00620_post():
   29  		RESPONSE = ""
   30  
   31  		import helpers.utils
   32  		param = ""
   33  		
   34  		for name in request.headers.keys():
   35  			if name.lower() in helpers.utils.commonHeaderNames:
   36  				continue
   37  		
   38  			if request.headers.get_all(name):
   39  				param = name
   40  				break
   41  
   42  		import base64
   43  		tmp = base64.b64encode(param.encode('utf-8'))
   44  		bar = base64.b64decode(tmp).decode('utf-8')
   45  
   46  		import helpers.utils
   47  
   48  		try:
   49  			fileName = f'{helpers.utils.TESTFILES_DIR}/{bar}'
   50> 			with open(fileName, 'wb') as fd:
   51  				RESPONSE += (
   52  					f'Now ready to write to file: {escape_for_html(fileName)}'
   53  				)
   54  		except IOError as e:
   55  			RESPONSE += (
   56  				f'Problem reading from file \'{escape_for_html(fileName)}\': '
   57  				f'{escape_for_html(e.strerror)}'
   58  			)
   59  
   60  		return RESPONSE
   61  
   62  
```
