# Label audit: sard-php (30 of 651 labelled alerts)
Mark each row: agree / disagree / unsure, comparing the label with the code.

## 1. CWE-79/191650.php:52 CWE-79 (semgrep echoed-request)
label: **safe** (entries ['sard-191650'])
verdict: 

```
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  <!DOCTYPE html>
   43  <html>
   44  <head/>
   45  <body>
   46  <?php
   47  $tainted = $_GET['UserData'];
   48  
   49  $tainted = http_build_query($tainted);
   50  
   51  
   52> echo "<div id='".  $tainted ."'>content</div>" ;
   53  ?>
   54  <h1>Hello World!</h1>
   55  </body>
   56  </html>
```

## 2. CWE-79/191233.php:52 CWE-79 (semgrep php-taint-xss)
label: **safe** (entries ['sard-191233'])
verdict: 

```
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  <!DOCTYPE html>
   43  <html>
   44  <head>
   45  <script>
   46  <?php
   47  $tainted = $_GET['UserData'];
   48  
   49  $tainted = (float) $tainted ;
   50  
   51  
   52> echo "alert(\"". $tainted ."\")" ;
   53  ?>
   54  </script>
   55  </head>
   56  <body>
   57  <h1>Hello World!</h1>
   58  </body>
   59  </html>
```

## 3. CWE-89/166280.php:59 CWE-89 (semgrep php-taint-sqli)
label: **safe** (entries ['sard-166280'])
verdict: 

```
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $sanitized = filter_var($tainted, FILTER_SANITIZE_NUMBER_INT);
   48  if (filter_var($sanitized, FILTER_VALIDATE_INT))
   49    $tainted = $sanitized ;
   50  else
   51    $tainted = "" ;
   52  
   53  $query = "SELECT * FROM COURSE c WHERE c.id IN (SELECT idcourse FROM REGISTRATION WHERE idstudent=' $tainted ')";
   54  
   55  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   56  mysql_select_db('dbname') ;
   57  echo "query : ". $query ."<br /><br />" ;
   58  
   59> $res = mysql_query($query);
   60  
   61  while($data =mysql_fetch_array($res)){
   62  print_r($data) ;
   63  echo "<br />" ;
   64  } 
   65  mysql_close($conn);
   66  
   67  ?>
```

## 4. CWE-78/167209.php:51 CWE-78 (semgrep php-taint-cmdi)
label: **safe** (entries ['sard-167209'])
verdict: 

```
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $tainted = preg_replace('/\'/', '', $tainted);
   48  
   49  $query = sprintf("ls '%s'", $tainted);
   50  
   51> $ret = system($query);
   52  
   53  
   54  ?>
```

## 5. CWE-98/167394.php:55 CWE-98 (semgrep php-taint-file-inclusion)
label: **safe** (entries ['sard-167394'])
verdict: 

```
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $legal_table = array("safe1", "safe2");
   48  if (in_array($tainted, $legal_table, true)) {
   49    $tainted = $tainted;
   50  } else {
   51    $tainted = $legal_table[0];
   52  }
   53  
   54  
   55> $var = include(sprintf("pages/'%d'.php", $tainted));
   56  
   57  
   58  
   59  ?>
```

## 6. CWE-89/174900.php:51 CWE-89 (semgrep tainted-sql-string)
label: **safe** (entries ['sard-174900'])
verdict: 

```
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted = (float) $tainted ;
   50  
   51> $query = sprintf("SELECT * FROM COURSE c WHERE c.id IN (SELECT idcourse FROM REGISTRATION WHERE idstudent=%d)", $tainted);
   52  
   53  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   54  mysql_select_db('dbname') ;
   55  echo "query : ". $query ."<br /><br />" ;
   56  
   57  $res = mysql_query($query);
   58  
   59  while($data =mysql_fetch_array($res)){
   60  print_r($data) ;
   61  echo "<br />" ;
   62  } 
   63  mysql_close($conn);
```

## 7. CWE-95/175171.php:56 CWE-95 (semgrep php-taint-code-injection)
label: **safe** (entries ['sard-175171'])
verdict: 

```
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  if (settype($tainted, "integer"))
   50    $tainted = $tainted ;
   51  else
   52    $tainted = 0 ;
   53  
   54  $query = sprintf("$temp = '%d';", $tainted);
   55  
   56> $res = eval($query);
   57  
   58  ?>
```

## 8. CWE-89/175911.php:63 CWE-89 (semgrep php-taint-sqli)
label: **safe** (entries ['sard-175911'])
verdict: 

```
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  class Sanitize{
   50    public function sanitize($input){
   51      return mysql_real_escape_string($input);
   52    }
   53  }
   54  $temp = new Sanitize();
   55  $tainted = $temp->sanitize($tainted);
   56  
   57  $query = "SELECT * FROM ' $tainted '";
   58  
   59  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   60  mysql_select_db('dbname') ;
   61  echo "query : ". $query ."<br /><br />" ;
   62  
   63> $res = mysql_query($query);
   64  
   65  while($data =mysql_fetch_array($res)){
   66  print_r($data) ;
   67  echo "<br />" ;
   68  } 
   69  mysql_close($conn);
   70  
   71  ?>
```

## 9. CWE-89/167176.php:55 CWE-89 (semgrep php-taint-sqli)
label: **safe** (entries ['sard-167176'])
verdict: 

```
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $tainted = mysql_real_escape_string($tainted);
   48  
   49  $query = sprintf("SELECT * FROM COURSE c WHERE c.id IN (SELECT idcourse FROM REGISTRATION WHERE idstudent='%d')", $tainted);
   50  
   51  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   52  mysql_select_db('dbname') ;
   53  echo "query : ". $query ."<br /><br />" ;
   54  
   55> $res = mysql_query($query);
   56  
   57  while($data =mysql_fetch_array($res)){
   58  print_r($data) ;
   59  echo "<br />" ;
   60  } 
   61  mysql_close($conn);
   62  
   63  ?>
```

## 10. CWE-95/166263.php:55 CWE-95 (semgrep php-taint-code-injection)
label: **safe** (entries ['sard-166263'])
verdict: 

```
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $sanitized = filter_var($tainted, FILTER_SANITIZE_NUMBER_INT);
   48  if (filter_var($sanitized, FILTER_VALIDATE_INT))
   49    $tainted = $sanitized ;
   50  else
   51    $tainted = "" ;
   52  
   53  $query = "$temp = ' $tainted ';";
   54  
   55> $res = eval($query);
   56  
   57  ?>
```

## 11. CWE-601/187337.php:58 CWE-601 (semgrep php-taint-open-redirect)
label: **safe** (entries ['sard-187337'])
verdict: 

```
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $re = "/^[a-zA-Z]*$/";
   50  if(preg_match($re, $tainted) == 1){
   51    $tainted = $tainted;
   52  }
   53  else{
   54    $tainted = "";
   55  }
   56  
   57  
   58> $var = header("'Location: " . $tainted .".php'");
   59  
   60  
   61  
   62  ?>
```

## 12. CWE-78/174886.php:53 CWE-78 (semgrep tainted-exec)
label: **safe** (entries ['sard-174886'])
verdict: 

```
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted = (float) $tainted ;
   50  
   51  $query = sprintf("find / size '%d'", $tainted);
   52  
   53> $ret = system($query);
   54  
   55  
   56  ?>
```

## 13. CWE-95/175121.php:56 CWE-95 (semgrep php-taint-code-injection)
label: **safe** (entries ['sard-175121'])
verdict: 

```
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  if(settype($tainted, "float"))
   50    $tainted = $tainted ;
   51  else
   52    $tainted = 0.0 ;
   53  
   54  $query = "$temp = '". $tainted . "';";
   55  
   56> $res = eval($query);
   57  
   58  ?>
```

## 14. CWE-78/163290.php:51 CWE-78 (semgrep tainted-exec)
label: **safe** (entries ['sard-163290'])
verdict: 

```
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $tainted += 0 ;
   48  
   49  $query = "find / size ' $tainted '";
   50  
   51> $ret = system($query);
   52  
   53  
   54  ?>
```

## 15. CWE-79/191343.php:55 CWE-79 (semgrep echoed-request)
label: **safe** (entries ['sard-191343'])
verdict: 

```
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  <!DOCTYPE html>
   43  <html>
   44  <head>
   45  <script>
   46  <?php
   47  $tainted = $_GET['UserData'];
   48  
   49  if(settype($tainted, "float"))
   50    $tainted = $tainted ;
   51  else
   52    $tainted = 0.0 ;
   53  
   54  
   55> echo "window.setInterval('". $tainted ."');" ;
   56  ?>
   57   </script>
   58  </head>
   59  <body>
   60  <h1>Hello World!</h1>
   61  </body>
   62  </html>
```

## 16. CWE-79/195651.php:54 CWE-79 (semgrep php-taint-xss)
label: **safe** (entries ['sard-195651'])
verdict: 

```
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  <!DOCTYPE html>
   43  <html>
   44  <head>
   45  <style>
   46  <?php
   47  $string = $_POST['UserData'] ;
   48  $tainted = unserialize($string);
   49      
   50  
   51  $tainted = (float) $tainted ;
   52  
   53  
   54> echo "body { color :\'". $tainted ."\' ; }" ;
   55  ?>
   56  </style> 
   57  </head>
   58  <body>
   59  <h1>Hello World!</h1>
   60  </body>
   61  </html>
```

## 17. CWE-98/175067.php:52 CWE-98 (semgrep php-taint-file-inclusion)
label: **safe** (entries ['sard-175067'])
verdict: 

```
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted = $tainted + 0;
   50  
   51  
   52> $var = include("pages/'". $tainted . "'.php");
   53  
   54  
   55  
   56  ?>
```

## 18. CWE-78/162584.php:57 CWE-78 (semgrep tainted-exec)
label: **safe** (entries ['sard-162584'])
verdict: 

```
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $re = "/^[0-9]*$/";
   48  if(preg_match($re, $tainted) == 1){
   49    $tainted = $tainted;
   50  }
   51  else{
   52    $tainted = "";
   53  }
   54  
   55  $query = "find / size '". $tainted . "'";
   56  
   57> $ret = system($query);
   58  
   59  
   60  ?>
```

## 19. CWE-98/174314.php:58 CWE-98 (semgrep php-taint-file-inclusion)
label: **safe** (entries ['sard-174314'])
verdict: 

```
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $re = "/^[0-9]*$/";
   50  if(preg_match($re, $tainted) == 1){
   51    $tainted = $tainted;
   52  }
   53  else{
   54    $tainted = "";
   55  }
   56  
   57  
   58> $var = include("pages/'". $tainted . "'.php");
   59  
   60  
   61  
   62  ?>
```

## 20. CWE-95/163287.php:51 CWE-95 (semgrep php-taint-code-injection)
label: **safe** (entries ['sard-163287'])
verdict: 

```
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $tainted += 0 ;
   48  
   49  $query = "$temp = ' $tainted ';";
   50  
   51> $res = eval($query);
   52  
   53  ?>
```

## 21. CWE-78/175030.php:53 CWE-78 (semgrep php-taint-cmdi)
label: **safe** (entries ['sard-175030'])
verdict: 

```
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted += 0 ;
   50  
   51  $query = sprintf("find / size '%d'", $tainted);
   52  
   53> $ret = system($query);
   54  
   55  
   56  ?>
```

## 22. CWE-601/185381.php:50 CWE-601 (semgrep php-taint-open-redirect)
label: **safe** (entries ['sard-185381'])
verdict: 

```
   26  
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $tainted = $tainted + 0;
   48  
   49  
   50> $var = header("Location: pages/'". $tainted . "'.php");
   51  
   52  
   53  
   54  ?>
```

## 23. CWE-78/174380.php:59 CWE-78 (semgrep php-taint-cmdi)
label: **safe** (entries ['sard-174380'])
verdict: 

```
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $re = "/^[a-zA-Z0-9]*$/";
   50  if(preg_match($re, $tainted) == 1){
   51    $tainted = $tainted;
   52  }
   53  else{
   54    $tainted = "";
   55  }
   56  
   57  $query = "cat '". $tainted . "'";
   58  
   59> $ret = system($query);
   60  
   61  
   62  ?>
```

## 24. CWE-78/174932.php:53 CWE-78 (semgrep tainted-exec)
label: **safe** (entries ['sard-174932'])
verdict: 

```
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted += 0.0 ;
   50  
   51  $query = "find / size '". $tainted . "'";
   52  
   53> $ret = system($query);
   54  
   55  
   56  ?>
```

## 25. CWE-89/167170.php:49 CWE-89 (semgrep tainted-sql-string)
label: **safe** (entries ['sard-167170'])
verdict: 

```
   25  
   26  
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_POST['UserData'];
   46  
   47  $tainted = mysql_real_escape_string($tainted);
   48  
   49> $query = sprintf("SELECT * FROM student where id='%u'", $tainted);
   50  
   51  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   52  mysql_select_db('dbname') ;
   53  echo "query : ". $query ."<br /><br />" ;
   54  
   55  $res = mysql_query($query);
   56  
   57  while($data =mysql_fetch_array($res)){
   58  print_r($data) ;
   59  echo "<br />" ;
   60  } 
   61  mysql_close($conn);
```

## 26. CWE-98/162580.php:56 CWE-98 (semgrep php-taint-file-inclusion)
label: **safe** (entries ['sard-162580'])
verdict: 

```
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $re = "/^[0-9]*$/";
   48  if(preg_match($re, $tainted) == 1){
   49    $tainted = $tainted;
   50  }
   51  else{
   52    $tainted = "";
   53  }
   54  
   55  
   56> $var = require(sprintf("pages/'%d'.php", $tainted));
   57  
   58  
   59  
   60  ?>
```

## 27. CWE-89/175555.php:51 CWE-89 (semgrep tainted-sql-string)
label: **safe** (entries ['sard-175555'])
verdict: 

```
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $tainted = mysql_real_escape_string($tainted);
   50  
   51> $query = sprintf("SELECT * FROM student where id='%u'", $tainted);
   52  
   53  $conn = mysql_connect('localhost', 'mysql_user', 'mysql_password');
   54  mysql_select_db('dbname') ;
   55  echo "query : ". $query ."<br /><br />" ;
   56  
   57  $res = mysql_query($query);
   58  
   59  while($data =mysql_fetch_array($res)){
   60  print_r($data) ;
   61  echo "<br />" ;
   62  } 
   63  mysql_close($conn);
```

## 28. CWE-601/185361.php:50 CWE-601 (semgrep php-taint-open-redirect)
label: **safe** (entries ['sard-185361'])
verdict: 

```
   26  
   27  
   28  
   29  
   30  
   31  
   32  
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $tainted = $_GET['UserData'];
   46  
   47  $tainted = (float) $tainted ;
   48  
   49  
   50> $var = header(sprintf("Location: pages/'%d'.php", $tainted));
   51  
   52  
   53  
   54  ?>
```

## 29. CWE-79/195761.php:57 CWE-79 (semgrep echoed-request)
label: **safe** (entries ['sard-195761'])
verdict: 

```
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  <!DOCTYPE html>
   43  <html>
   44  <head/>
   45  <body>
   46  <?php
   47  $string = $_POST['UserData'] ;
   48  $tainted = unserialize($string);
   49      
   50  
   51  if (settype($tainted, "integer"))
   52    $tainted = $tainted ;
   53  else
   54    $tainted = 0 ;
   55  
   56  
   57> echo "<".  $tainted ." href= \"/bob\" />" ;
   58  ?>
   59  <h1>Hello World!</h1>
   60  </body>
   61  </html>
```

## 30. CWE-95/174648.php:57 CWE-95 (semgrep php-taint-code-injection)
label: **safe** (entries ['sard-174648'])
verdict: 

```
   33  
   34  
   35  
   36  
   37  
   38  
   39  
   40  
   41  
   42  
   43  
   44  
   45  $string = $_POST['UserData'] ;
   46  $tainted = unserialize($string);
   47      
   48  
   49  $sanitized = filter_var($tainted, FILTER_SANITIZE_NUMBER_INT);
   50  if (filter_var($sanitized, FILTER_VALIDATE_INT))
   51    $tainted = $sanitized ;
   52  else
   53    $tainted = "" ;
   54  
   55  $query = "$temp = ' $tainted ';";
   56  
   57> $res = eval($query);
   58  
   59  ?>
```
