# SQL Injection

Author: Inndy < inndy [dot] tw [at] gmail [dot] com >

Date: 2016/08/04

## 開始之前

現代的網站提供了各式各樣精彩的服務，並且大多數的網站都需要在伺服器上面保存一些資料，這些資料除了圖片、影片、壓縮檔...之類的附件素材之外，諸如使用者資訊、文章內容、交易資料...等，通常會放在資料庫內保存，今天要介紹的是針對資料庫的攻擊。

**以下內容僅供學習研究用途，請勿用於非法入侵。**

## SQL 是什麼？

Structured Query Language，一種用來跟關聯式資料庫（relational database）溝通的語言，可以在資料庫裡面查詢、新增、修改、刪除資料，也可以對資料庫進行管理。

如果我想要查詢使用者的資料，我可能會對資料庫下以下的 SQL：

```sql
SELECT * FROM `users`;
```

使用大寫是寫 SQL 時的一個慣例，屬於 SQL 保留字的部分採用大寫，其餘開發者自行命名的部分通常採用小寫。這個 SQL 會告訴資料庫，我想要讀取 `users` 這個資料表的內容，並且把所有的東西都讀出來給我。

讀到這裡，如果你還看不懂下面的東西，你可以先參考這些東西去補充一些相關知識。

## Injection？

當你看到 Injection 這個字的時候，就表示某個使用者在某個地方操作時，輸入的資料未經過檢查就被放進了某些地方執行，而使用者可以用某種方式「結束資料表示區段」，例如 Python 使用單引號或者雙引號表示一個字串，如果你輸入的使用者名稱會經由註冊程式，被寫入一個 Python script 檔案然後執行，當你輸入 `Inndy` 時，會產生以下內容：

```python
from time import time

with open("users-list.html", "a") as f:
    f.write("Name: Inndy\n")
    f.write("Register time: " + str(time()) + "\n")
```

那麼如果我輸入了：`" + open("../super-secret.txt").read() + "`，最後註冊程式就會執行：

```python
from time import time

with open("users-list.html", "a") as f:
    f.write("Name: " + open("../super-secret.txt").read() + "\n")
    f.write("Register time: " + str(time()) + "\n")
```

接著你就可以在使用者列表上的網頁上看到 `super-secret.txt` 的內容了

## SQL Injection 是什麼？

現今網站以 PHP + MySQL 為大宗，所以以下舉例就是這個組合。

資料表 `users`：

- id -> int, auto_increment
- name -> varchar(255), not null
- password -> char(40), not null
    - 不良示範，密碼請使用更強的雜湊演算法，[詳情請見這裡](000-201607-1.不要儲存明文密碼.md)
- is_admin -> int

考慮以下程式碼：

```php
<?php
function login($user, $pass) {
    $sql = "SELECT * FROM `users` WHERE `name` = '{$user}' AND `password` = SHA1('{$pass}')";
    $user = query($sql);
    if (count($user) > 0)
        return $user[0];
    else
        return false;
}

$user = login($_POST['user'], $_POST['pass']);
if ($user !== false) {
    echo "登入成功：" . $user['name'];
    if ($user['is_admin']) {
        echo "\n你是網站管理員";
    }
} else {
    echo "登入失敗！";
}
```

如果我們想要在不知道帳號密碼的狀況下登入這個系統，那麼我們可以輸入 `name` = `' or 1 = 1 --` 而密碼隨意，那麼 SQL 語句組合後就會變成

```sql
SELECT * FROM `users` WHERE `name` = '' or 1 = 1 --' AND `password` = SHA1('123123123')
```

你可以看到第一個單引號結束了這個字串，而 `--` 是 MySQL 的註解，接著這個 SQL 語句就變成了無論如何都會成立的檢查。

到這裡，你應該知道了要如何利用 SQL Injection 繞過檢查，對於真實環境的攻擊（或黑箱安全測試），你要猜測網站內的 SQL 語句是怎麼寫的，注入點在什麼地方，可能用的是雙引號字串，或者數字的欄位根本沒有用引號，有可能有括號，也有可能有多個括號，猜到了才有辦法進行攻擊。

總結一下攻擊步驟：

1. 猜 SQL 語句結構
2. 關閉字串並且補上括號結尾
3. DO EVERYTHING YOU WANT
4. 用註解使後面的 SQL 語句失去作用（不一定需要）

## 其他的攻擊方式

剛剛我示範了如何繞過登入檢查，現在我們來講講其他攻擊方式，讓你可以從資料庫的其他地方撈出資料。

### UNION Based

如果是 `SELECT` 語句的狀況下，可以用 `UNION SELECT` 的方式，偽造結果或者是讀取其他資料表的內容。

如： `' UNION SELECT 1, 'QQ', '', 1 --` 這組攻擊可以讓你登入，並且使用者名稱是 `QQ`，並且具有管理員權限。當然你也可以讀取別的資料表。

### Error Message Based

有些天真的開發者把資料庫回傳的錯誤訊息給直接印出來了，正確的做法是把任何的錯誤訊息給寫入檔案或是資料庫記錄下來，印出來給使用者會發生不好的事。MySQL 可以利用錯誤訊息把資料給帶出來。

[這裡有個例子](https://www.notsosecure.com/mysql-exploitation-with-error-messages/)

### Boolean Based

沒有錯誤訊息，但是可以判斷 SQL 語句執行成功或否（例如：無法登入、顯示操作失敗的訊息）的狀況下，可以一次洩漏一個 bit 的資料，對於數字可以做 binary search，對於文字資料可以一次洩漏一個 bit 慢慢拼出來。

### Time Based

連錯誤訊息都沒有，無從判斷 SQL 成功與否，那麼可以做的事情是[旁道攻擊](https://en.wikipedia.org/wiki/Side-channel_attack)，網站通常會等待 SQL 執行完成後才繼續，所以我們可以讓 SQL 執行久一點的方式來洩漏資料，接下來的攻擊方式就跟 Boolean Based 一樣。

邏輯大概如下：

```python
if bits(data)[0] == 1:
    delay(10)
else:
    return
```

如果發現這個 HTTP 請求過了很久才返回，那就表示被延遲了，藉此讀取資料。

## 自動化攻擊

- [sqlmap](http://sqlmap.org/)
- [sqlninja](http://sqlninja.sourceforge.net/)

## 解決方式

1. 使用 ORM，如：[LazyRecord](https://github.com/corneltek/LazyRecord), [Illuminate Database](https://github.com/illuminate/database) (Laravel 的 Eloquent 獨立版本)，或是考慮挑一個 PHP Framework 使用內建的 ORM 如 [Laravel](https://laravel.com/)
2. [mysqli prepared statement](http://php.net/manual/en/mysqli.quickstart.prepared-statements.php)
3. [PDO with parameter binding](http://php.net/manual/en/pdostatement.bindparam.php)
4. [mysqli::real\_escape\_string](http://php.net/manual/en/mysqli.real-escape-string.php)
    - 不推薦這個方法，需要正確設定文字編碼才有效
    - [real\_escape\_string 被繞過的例子](http://stackoverflow.com/questions/5741187/sql-injection-that-gets-around-mysql-real-escape-string)
5. 先使用[正規表達式](https://zh.wikipedia.org/wiki/正規表達式)檢查資料
    - 不推薦這個方法，你寫的正規表達式可能有漏網之魚

不論你使用以上任何一種解決方式，切記：自己用字串拼接或是 `sprintf` 組合 SQL 語句，就有可能被攻擊

## 下集預告

(nil)

---

這篇文章以 [CC BY-NC-SA 3.0](https://creativecommons.org/licenses/by-nc-sa/3.0/tw/) 授權釋出
