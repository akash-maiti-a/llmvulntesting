# Label audit: xvwa (19 of 19 labelled alerts)
Mark each row: agree / disagree / unsure, comparing the label with the code.

## 1. vulnerabilities/reflected_xss/home.php:32 CWE-79 (semgrep php-taint-xss)
label: **vulnerable** (entries ['xvwa-reflected_xss-home'])
verdict: 

```
    8  
    9          
   10          <p align="justify">
   11  
   12          </p>
   13  
   14  
   15  
   16      </div>
   17  
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your message here.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter URL of Image" name="item"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30              <?php
   31                  if (isset($_GET['item'])) {
   32>                     echo $_GET['item'];
   33                  }
   34                  
   35              ?>
   36          </p>
   37      </div>
   38        
   39      <hr>
   40      
   41  </div>
   42  <?php include_once('../../about.html'); ?>
   43  
```

## 2. vulnerabilities/reflected_xss/home.php:32 CWE-79 (semgrep echoed-request)
label: **vulnerable** (entries ['xvwa-reflected_xss-home'])
verdict: 

```
    8  
    9          
   10          <p align="justify">
   11  
   12          </p>
   13  
   14  
   15  
   16      </div>
   17  
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your message here.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter URL of Image" name="item"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30              <?php
   31                  if (isset($_GET['item'])) {
   32>                     echo $_GET['item'];
   33                  }
   34                  
   35              ?>
   36          </p>
   37      </div>
   38        
   39      <hr>
   40      
   41  </div>
   42  <?php include_once('../../about.html'); ?>
   43  
```

## 3. vulnerabilities/sqli_blind/home.php:55 CWE-89 (semgrep php-taint-sqli)
label: **vulnerable** (entries ['xvwa-sqli_blind-home'])
verdict: 

```
   31                              if($conn->connect_errno > 0){
   32                                  echo "Error in connecting to database";
   33                              }else{ 
   34                                  $sql = 'select itemid from caffaine';
   35                                  $result = $conn->query($sql);
   36                                  while($rows = $result->fetch_assoc()){
   37                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   38                                  }
   39                              } 
   40  
   41                              echo "</select><br>";
   42                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   43                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   44                              echo "</div> </form> </p>";
   45                              echo " </div>";
   46                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   47                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   48                              $isSearch = false;
   49                              if(($item!="") && $search!=""){ 
   50                                  echo "<br><ul class=\"featureList\">";
   51                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   52                                  echo "</ul>";
   53                              }else if($item){
   54                                  $sql = "select * from caffaine where itemid = ".$item;
   55>                                 $result = $conn->query($sql);
   56                                  $rowcount = $result->num_rows;
   57                                  if($rowcount>0){
   58                                      $isSearch = true;
   59                                  }
   60                              }else if($search){
   61                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   62                                  $result = $conn->query($sql);
   63                                  $rowcount = $result->num_rows;
   64                                  if($rowcount>0){
   65                                      $isSearch = true;
   66                                  }
   67                              }
```

## 4. vulnerabilities/fi/home.php:36 CWE-98 (semgrep php-taint-file-inclusion)
label: **vulnerable** (entries ['xvwa-fi-home'])
verdict: 

```
   12          </p>
   13          <p>Read more about File Inclusions <br>
   14  
   15  
   16  
   17          </p>
   18  
   19      </div>
   20  
   21  </div>
   22  
   23  <div class="well">
   24  
   25      <p>
   26          <form method="get" action="">
   27              <div class="form-group">
   28                  <br>
   29                  <div class="text-left">
   30                  <?php 
   31                      $f='readme.txt';
   32                      echo "<a class=\"btn btn-primary\" href=\".?file=$f\" /> Click here </a><br><br>";
   33  
   34                      if (isset($_GET['file'])) {
   35                          $file=$_GET['file'];
   36>                         include($file);
   37                      }                 
   38                  ?>
   39                  </div>
   40              </div>
   41          </form>
   42      </p>
   43  
   44        
   45      <hr>
   46      
   47  </div>
   48  <?php include_once('../../about.html'); ?>
```

## 5. vulnerabilities/sqli_blind/home.php:62 CWE-89 (semgrep php-taint-sqli)
label: **vulnerable** (entries ['xvwa-sqli_blind-home'])
verdict: 

```
   38                                  }
   39                              } 
   40  
   41                              echo "</select><br>";
   42                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   43                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   44                              echo "</div> </form> </p>";
   45                              echo " </div>";
   46                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   47                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   48                              $isSearch = false;
   49                              if(($item!="") && $search!=""){ 
   50                                  echo "<br><ul class=\"featureList\">";
   51                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   52                                  echo "</ul>";
   53                              }else if($item){
   54                                  $sql = "select * from caffaine where itemid = ".$item;
   55                                  $result = $conn->query($sql);
   56                                  $rowcount = $result->num_rows;
   57                                  if($rowcount>0){
   58                                      $isSearch = true;
   59                                  }
   60                              }else if($search){
   61                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   62>                                 $result = $conn->query($sql);
   63                                  $rowcount = $result->num_rows;
   64                                  if($rowcount>0){
   65                                      $isSearch = true;
   66                                  }
   67                              }
   68                              if($isSearch){
   69                                  echo "<table>";
   70                                  while($rows = $result->fetch_assoc()){
   71                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   72                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
   73                                      echo "<td><img src='".$rows['itemdisplay']."' height=130 weight=20/></td>";
   74                                      echo "<tr><td><b>Category : </b>".$rows['categ']."</td></tr>";
```

## 6. vulnerabilities/cmdi/home.php:38 CWE-78 (semgrep php-taint-cmdi)
label: **vulnerable** (entries ['xvwa-cmdi-home'])
verdict: 

```
   14  
   15  
   16      </div>
   17      
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your IP/host to ping.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter IP/HOSTNAME to Ping" name="target"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30          </p>
   31      </div>
   32              <?php
   33              if (isset($_REQUEST['target'])) {
   34                  $target = $_REQUEST['target'];
   35                  if($target){
   36                      if (stristr(php_uname('s'), 'Windows NT')) { 
   37              
   38>                     $cmd = shell_exec( 'ping  ' . $target );
   39                      echo '<pre>'.$cmd.'</pre>';
   40  
   41                      } else { 
   42                          $cmd = shell_exec( 'ping  -c 3 ' . $target );
   43                          echo '<pre>'.$cmd.'</pre>';
   44                      }
   45                  }
   46              }
   47                  
   48              ?>
   49          
   50        
```

## 7. vulnerabilities/ssrf_xspa/home.php:33 CWE-918 (semgrep tainted-filename)
label: **vulnerable** (entries ['xvwa-ssrf_xspa-home'])
verdict: 

```
    9          
   10          <p align="justify">
   11  
   12          </p>
   13          <p>Read more about SSRF <br>
   14          <strong><a target="_blank" href="https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit">https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit</a></p></strong>
   15  
   16      </div>
   17  
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter an image URL from remote server or internet.  
   23              <form method='post' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter URL of Image" name="img_url"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30              <?php
   31                  $image = "";
   32                  if(isset($_POST['img_url'])){
   33>                     $remote_content = file_get_contents($_POST['img_url']);
   34                      $filename = "../../img/".rand()."img1.jpg";
   35                      file_put_contents($filename, $remote_content);
   36                      echo $_POST['img_url']."<br>";
   37                      $image = "<img src=\"".$filename."\" width=\"100\" height=\"100\" />";
   38                  }
   39                  echo $image;
   40              
   41              ?>
   42          </p>
   43      </div>
   44        
   45      <hr>
```

## 8. vulnerabilities/cmdi/home.php:42 CWE-78 (semgrep tainted-exec)
label: **vulnerable** (entries ['xvwa-cmdi-home'])
verdict: 

```
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your IP/host to ping.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter IP/HOSTNAME to Ping" name="target"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30          </p>
   31      </div>
   32              <?php
   33              if (isset($_REQUEST['target'])) {
   34                  $target = $_REQUEST['target'];
   35                  if($target){
   36                      if (stristr(php_uname('s'), 'Windows NT')) { 
   37              
   38                      $cmd = shell_exec( 'ping  ' . $target );
   39                      echo '<pre>'.$cmd.'</pre>';
   40  
   41                      } else { 
   42>                         $cmd = shell_exec( 'ping  -c 3 ' . $target );
   43                          echo '<pre>'.$cmd.'</pre>';
   44                      }
   45                  }
   46              }
   47                  
   48              ?>
   49          
   50        
   51      <hr>
   52      
   53  </div>
   54  
```

## 9. vulnerabilities/sqli/home.php:60 CWE-89 (semgrep tainted-sql-string)
label: **vulnerable** (entries ['xvwa-sqli-home'])
verdict: 

```
   36                                  $sql = 'select itemid from caffaine';
   37                                  $result = $conn->query($sql);
   38                                  while($rows = $result->fetch_assoc()) {
   39                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   40                                  }
   41                              } 
   42  
   43                              echo "</select><br>";
   44                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   45                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   46                              echo "</div> </form> </p>";
   47                              echo "</div>";
   48                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   49                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   50                              $isSearch = false;
   51                              if(($item!="") && $search!=""){ 
   52                                  echo "<br><ul class=\"featureList\">";
   53                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   54                                  echo "</ul>";
   55                              }else if($item){
   56                                  $sql = "select * from caffaine where itemid = ".$item;
   57                                  $result = $conn->query($sql);
   58                                  $isSearch = true;
   59                              }else if($search){
   60>                                 $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   61                                  $result = $conn->query($sql);
   62                                  $isSearch = true;
   63                              }
   64                              if($isSearch){
   65                                  echo "<table>";
   66                                  while($rows = $result->fetch_assoc()){
   67                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   68                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
   69                                      echo "<td><img src='".$rows['itemdisplay']."' height=130 weight=20/></td>";
   70                                      echo "<tr><td><b>Category : </b>".$rows['categ']."</td></tr>";
   71                                      echo "<tr><td><b>Price : </b>".$rows['price']."$</td></tr>"; 
   72                                      echo "<tr><td colspan=3><hr></td></tr>";
```

## 10. vulnerabilities/redirect/redirect.php:5 CWE-601 (semgrep php-taint-open-redirect)
label: **vulnerable** (entries ['xvwa-redirect-redirect'])
verdict: 

```
    1  <?php 
    2  	if (isset($_GET['forward'])){
    3  		$forward=$_GET['forward'];
    4  		if (strlen($forward)>0){
    5> 			header("Location: ".$forward);
    6  		}
    7  	}
    8  ?>
```

## 11. vulnerabilities/sqli/home.php:57 CWE-89 (semgrep php-taint-sqli)
label: **vulnerable** (entries ['xvwa-sqli-home'])
verdict: 

```
   33                              if($conn->connect_errno > 0){
   34                                  echo "Error in connecting to database";
   35                              }else{
   36                                  $sql = 'select itemid from caffaine';
   37                                  $result = $conn->query($sql);
   38                                  while($rows = $result->fetch_assoc()) {
   39                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   40                                  }
   41                              } 
   42  
   43                              echo "</select><br>";
   44                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   45                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   46                              echo "</div> </form> </p>";
   47                              echo "</div>";
   48                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   49                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   50                              $isSearch = false;
   51                              if(($item!="") && $search!=""){ 
   52                                  echo "<br><ul class=\"featureList\">";
   53                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   54                                  echo "</ul>";
   55                              }else if($item){
   56                                  $sql = "select * from caffaine where itemid = ".$item;
   57>                                 $result = $conn->query($sql);
   58                                  $isSearch = true;
   59                              }else if($search){
   60                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   61                                  $result = $conn->query($sql);
   62                                  $isSearch = true;
   63                              }
   64                              if($isSearch){
   65                                  echo "<table>";
   66                                  while($rows = $result->fetch_assoc()){
   67                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   68                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
   69                                      echo "<td><img src='".$rows['itemdisplay']."' height=130 weight=20/></td>";
```

## 12. vulnerabilities/php_object_injection/home.php:38 CWE-502 (semgrep php-taint-unserialize)
label: **vulnerable** (entries ['xvwa-php_object_injection-home'])
verdict: 

```
   14      <div class="well">
   15          <p>
   16              <form method="get" action="">
   17                  <div class="form-group">
   18                      <div class="text-left">
   19                          <label></label>
   20                      <div class="form-group" align="left"> 
   21                          <a class="btn btn-primary" href='?r=a:2:{i:0;s:4:"XVWA";i:1;s:33:"Example Web Application";}' type="submit">CLICK HERE</a>
   22                      </div>
   23                          <?php 
   24  
   25                                  public $inject;
   26                                  function __construct(){
   27  
   28                                  }
   29  
   30                                  function __wakeup(){
   31                                      if(isset($this->inject)){
   32                                          eval($this->inject);
   33                                      }
   34                                  }
   35                              }
   36                              if(isset($_REQUEST['r'])){  
   37  
   38>                                 $var1=unserialize($_REQUEST['r']);
   39                                  
   40  
   41                                  if(is_array($var1)){ 
   42                                      echo "<br/>".$var1[0]." - ".$var1[1];
   43                                  }
   44                              }else{
   45                                  echo ""; # nothing happens here
   46                              }
   47                          ?>
   48           </div>
   49       </div>
   50   </form>
```

## 13. vulnerabilities/cmdi/home.php:42 CWE-78 (semgrep php-taint-cmdi)
label: **vulnerable** (entries ['xvwa-cmdi-home'])
verdict: 

```
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your IP/host to ping.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter IP/HOSTNAME to Ping" name="target"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30          </p>
   31      </div>
   32              <?php
   33              if (isset($_REQUEST['target'])) {
   34                  $target = $_REQUEST['target'];
   35                  if($target){
   36                      if (stristr(php_uname('s'), 'Windows NT')) { 
   37              
   38                      $cmd = shell_exec( 'ping  ' . $target );
   39                      echo '<pre>'.$cmd.'</pre>';
   40  
   41                      } else { 
   42>                         $cmd = shell_exec( 'ping  -c 3 ' . $target );
   43                          echo '<pre>'.$cmd.'</pre>';
   44                      }
   45                  }
   46              }
   47                  
   48              ?>
   49          
   50        
   51      <hr>
   52      
   53  </div>
   54  
```

## 14. vulnerabilities/sqli/home.php:61 CWE-89 (semgrep php-taint-sqli)
label: **vulnerable** (entries ['xvwa-sqli-home'])
verdict: 

```
   37                                  $result = $conn->query($sql);
   38                                  while($rows = $result->fetch_assoc()) {
   39                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   40                                  }
   41                              } 
   42  
   43                              echo "</select><br>";
   44                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   45                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   46                              echo "</div> </form> </p>";
   47                              echo "</div>";
   48                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   49                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   50                              $isSearch = false;
   51                              if(($item!="") && $search!=""){ 
   52                                  echo "<br><ul class=\"featureList\">";
   53                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   54                                  echo "</ul>";
   55                              }else if($item){
   56                                  $sql = "select * from caffaine where itemid = ".$item;
   57                                  $result = $conn->query($sql);
   58                                  $isSearch = true;
   59                              }else if($search){
   60                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   61>                                 $result = $conn->query($sql);
   62                                  $isSearch = true;
   63                              }
   64                              if($isSearch){
   65                                  echo "<table>";
   66                                  while($rows = $result->fetch_assoc()){
   67                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   68                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
   69                                      echo "<td><img src='".$rows['itemdisplay']."' height=130 weight=20/></td>";
   70                                      echo "<tr><td><b>Category : </b>".$rows['categ']."</td></tr>";
   71                                      echo "<tr><td><b>Price : </b>".$rows['price']."$</td></tr>"; 
   72                                      echo "<tr><td colspan=3><hr></td></tr>";
   73                                  }
```

## 15. vulnerabilities/sqli_blind/home.php:61 CWE-89 (semgrep tainted-sql-string)
label: **vulnerable** (entries ['xvwa-sqli_blind-home'])
verdict: 

```
   37                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   38                                  }
   39                              } 
   40  
   41                              echo "</select><br>";
   42                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   43                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   44                              echo "</div> </form> </p>";
   45                              echo " </div>";
   46                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   47                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   48                              $isSearch = false;
   49                              if(($item!="") && $search!=""){ 
   50                                  echo "<br><ul class=\"featureList\">";
   51                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   52                                  echo "</ul>";
   53                              }else if($item){
   54                                  $sql = "select * from caffaine where itemid = ".$item;
   55                                  $result = $conn->query($sql);
   56                                  $rowcount = $result->num_rows;
   57                                  if($rowcount>0){
   58                                      $isSearch = true;
   59                                  }
   60                              }else if($search){
   61>                                 $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   62                                  $result = $conn->query($sql);
   63                                  $rowcount = $result->num_rows;
   64                                  if($rowcount>0){
   65                                      $isSearch = true;
   66                                  }
   67                              }
   68                              if($isSearch){
   69                                  echo "<table>";
   70                                  while($rows = $result->fetch_assoc()){
   71                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   72                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
   73                                      echo "<td><img src='".$rows['itemdisplay']."' height=130 weight=20/></td>";
```

## 16. vulnerabilities/redirect/home.php:31 CWE-601 (semgrep php-taint-open-redirect)
label: **vulnerable** (entries ['xvwa-redirect-home'])
verdict: 

```
    7          </p>
    8  
    9  
   10  
   11      </div>
   12  
   13  </div>
   14  <div class="well">
   15      <p>
   16          <form method="get" action="">
   17              <div class="form-group">
   18                  <div class="text-left">
   19  
   20                  <strong>
   21  
   22  
   23                  </strong>
   24                  <?php 
   25                      
   26                      if (isset($_GET['forward'])){
   27                          $forward=$_GET['forward'];
   28                          if (strlen($forward)>0){
   29                              ob_start();
   30                              ob_end_flush(); 
   31>                             header("Location: ".$forward);
   32                          }
   33                      }
   34                  ?>
   35                  </div>
   36              </div>
   37          </form>
   38      </p>      
   39      <hr>
   40      
   41  </div>
   42  <?php include_once('../../about.html'); ?>
```

## 17. vulnerabilities/sqli_blind/home.php:54 CWE-89 (semgrep tainted-sql-string)
label: **vulnerable** (entries ['xvwa-sqli_blind-home'])
verdict: 

```
   30                              include('../../config.php');
   31                              if($conn->connect_errno > 0){
   32                                  echo "Error in connecting to database";
   33                              }else{ 
   34                                  $sql = 'select itemid from caffaine';
   35                                  $result = $conn->query($sql);
   36                                  while($rows = $result->fetch_assoc()){
   37                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   38                                  }
   39                              } 
   40  
   41                              echo "</select><br>";
   42                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   43                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   44                              echo "</div> </form> </p>";
   45                              echo " </div>";
   46                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   47                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   48                              $isSearch = false;
   49                              if(($item!="") && $search!=""){ 
   50                                  echo "<br><ul class=\"featureList\">";
   51                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   52                                  echo "</ul>";
   53                              }else if($item){
   54>                                 $sql = "select * from caffaine where itemid = ".$item;
   55                                  $result = $conn->query($sql);
   56                                  $rowcount = $result->num_rows;
   57                                  if($rowcount>0){
   58                                      $isSearch = true;
   59                                  }
   60                              }else if($search){
   61                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   62                                  $result = $conn->query($sql);
   63                                  $rowcount = $result->num_rows;
   64                                  if($rowcount>0){
   65                                      $isSearch = true;
   66                                  }
```

## 18. vulnerabilities/sqli/home.php:56 CWE-89 (semgrep tainted-sql-string)
label: **vulnerable** (entries ['xvwa-sqli-home'])
verdict: 

```
   32                              include('../../config.php');
   33                              if($conn->connect_errno > 0){
   34                                  echo "Error in connecting to database";
   35                              }else{
   36                                  $sql = 'select itemid from caffaine';
   37                                  $result = $conn->query($sql);
   38                                  while($rows = $result->fetch_assoc()) {
   39                                      echo "<option value=\"".$rows['itemid']."\">".$rows['itemid']."</option>";
   40                                  }
   41                              } 
   42  
   43                              echo "</select><br>";
   44                              echo "<input class=\"form-control\" width=\"50%\" placeholder=\"Search\" name=\"search\"></input> <br>";
   45                              echo "<div align=\"right\"> <button class=\"btn btn-default\" type=\"submit\">Submit</button></div>";
   46                              echo "</div> </form> </p>";
   47                              echo "</div>";
   48                              $item = isset($_POST['item']) ? $_POST['item'] : '';
   49                              $search = isset($_POST['search']) ? $_POST['search'] : '';
   50                              $isSearch = false;
   51                              if(($item!="") && $search!=""){ 
   52                                  echo "<br><ul class=\"featureList\">";
   53                                  echo "<li class=\"cross\">Error! Can not use both search and itemcode option. Search using either of these optoins.</li>";
   54                                  echo "</ul>";
   55                              }else if($item){
   56>                                 $sql = "select * from caffaine where itemid = ".$item;
   57                                  $result = $conn->query($sql);
   58                                  $isSearch = true;
   59                              }else if($search){
   60                                  $sql = "SELECT * FROM caffaine WHERE itemname LIKE '%" . $search . "%' OR itemdesc LIKE '%" . $search . "%' OR categ LIKE '%" . $search . "%'";
   61                                  $result = $conn->query($sql);
   62                                  $isSearch = true;
   63                              }
   64                              if($isSearch){
   65                                  echo "<table>";
   66                                  while($rows = $result->fetch_assoc()){
   67                                      echo "<tr><td><b>Item Code : </b>".$rows['itemcode']."</td><td rowspan=5>&nbsp;&nbsp;</td><td rowspan=5 valign=\"top\" align=\"justify\"><b>Description : </b>".$rows['itemdesc']."</td></tr>";
   68                                      echo "<tr><td><b>Item Name : </b>".$rows['itemname']."</td></tr>";
```

## 19. vulnerabilities/cmdi/home.php:38 CWE-78 (semgrep tainted-exec)
label: **vulnerable** (entries ['xvwa-cmdi-home'])
verdict: 

```
   14  
   15  
   16      </div>
   17      
   18  </div>
   19  
   20  <div class="well">
   21      <div class="col-lg-6"> 
   22          <p>Enter your IP/host to ping.  
   23              <form method='get' action=''>
   24                  <div class="form-group"> 
   25                      <label></label>
   26                      <input class="form-control" width="50%" placeholder="Enter IP/HOSTNAME to Ping" name="target"></input> <br>
   27                      <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
   28                 </div> 
   29              </form>
   30          </p>
   31      </div>
   32              <?php
   33              if (isset($_REQUEST['target'])) {
   34                  $target = $_REQUEST['target'];
   35                  if($target){
   36                      if (stristr(php_uname('s'), 'Windows NT')) { 
   37              
   38>                     $cmd = shell_exec( 'ping  ' . $target );
   39                      echo '<pre>'.$cmd.'</pre>';
   40  
   41                      } else { 
   42                          $cmd = shell_exec( 'ping  -c 3 ' . $target );
   43                          echo '<pre>'.$cmd.'</pre>';
   44                      }
   45                  }
   46              }
   47                  
   48              ?>
   49          
   50        
```
