# China-Focused Vendor & Technology Fingerprints

Security testing fingerprints for Chinese enterprise software, middleware, and network equipment. Organized by product category. Use these fingerprints for target identification during reconnaissance.

---

## Enterprise OA Systems

### Seeyon (致远互联)

```yaml
fingerprints:
  - title: "Seeyon OA"
  - detection:
      - path: "/seeyon"
      - title: Contains "致远" or "Seeyon"
      - cookie: "JSESSIONID"
      - icon_hash: "-1655653066"  # seeyon favicon
  - default_paths:
      - "/seeyon/index.jsp"
      - "/seeyon/login/Login.jsp"
      - "/seeyon/main/index.jsp"
      - "/seeyon/thirdparty"
  - sensitive_paths:
      - "/seeyon/individual/email"
      - "/seeyon/individual/calendar"
      - "/seeyon/individual/document"
      - "/seeyon/rest/orgDepartment/list"
      - "/seeyon/rest/orgEmployee/list"
      - "/seeyon/rest/m3/common/permissionPermission" # info leak
```

### Tongda (通达OA)

```yaml
fingerprints:
  - title: "Tongda OA"
  - detection:
      - path: "/"
      - title: Contains "通达OA"
      - body: Contains "/static/touch"
      - header: "Server: Tongda"
  - default_paths:
      - "/login.php"
      - "/general/index.php"
      - "/module/index.php"
      - "/static/"
  - sensitive_paths:
      - "/inc/reg_globals.php"
      - "/general/data_center/export.php"
      - "/general/meeting/detail.php"
      - "/ispirit/login_code.php"   # auth bypass (old)
      - "/general/email"
```

### Weaver / Ecology (泛微)

```yaml
fingerprints:
  - title: "Weaver Ecology OA"
  - detection:
      - path: "/"
      - body: Contains "/wui/"
      - cookie: "ecology_JSessionId"
      - logo: "/theme/ecology-logo.png"
  - default_paths:
      - "/login.jsp"
      - "/wui/index.html"
      - "/wui/theme/ecology3/skin/js/init.js"
  - sensitive_paths:
      - "/E-mobile/login"     # mobile access
      - "/api/portal"         # API access
      - "/cloudstore/"
      - "/emailconv/"
      - "/workflow/"
```

### Wanhu (万户OA)

```yaml
fingerprints:
  - title: "Wanhu OA"
  - detection:
      - path: "/"
      - title: Contains "万户" or "WHOA"
      - body: Contains "zanhu.com" or "whir.net"
  - default_paths:
      - "/defaultroot/index.jsp"
      - "/defaultroot/login.jsp"
      - "/defaultroot/main.jsp"
  - sensitive_paths:
      - "/defaultroot/upload/"
      - "/defaultroot/config/"
      - "/defaultroot/backup/"
```

### Yonyou (用友)

```yaml
fingerprints:
  - title: "Yonyou NC / U8"
  - detection:
      - path: "/"
      - title: Contains "用友" or "Yonyou"
      - cookie: "iUFontSize"
  - default_paths:
      - "/login.jsp"
      - "/nc/index.jsp"
      - "/index.jsp"
      - "/yonyou/"
  - sensitive_paths:
      - "/service/~cumt/ctd"
      - "/service/~x3/debugger"
      - "/NCFindWeb"
      - "/fs/"                # file server
```

### Kingdee (金蝶)

```yaml
fingerprints:
  - title: "Kingdee"
  - detection:
      - path: "/"
      - title: Contains "金蝶" or "Kingdee"
      - body: Contains "easweb"
  - default_paths:
      - "/easportal/"
      - "/kingdee/"
      - "/portal/"
  - sensitive_paths:
      - "/easportal/tools/"
      - "/appspec/"
```

### Landray (蓝凌OA)

```yaml
fingerprints:
  - title: "Landray OA"
  - detection:
      - path: "/"
      - body: Contains "kmss" or "Landray"
  - default_paths:
      - "/kmss/index.jsp"
      - "/kmreview/"
      - "/sys/"
  - sensitive_paths:
      - "/kmss/api/"
```

---

## Chinese CMS / Frameworks

### DedeCMS (织梦)

```yaml
fingerprints:
  - fingerprint: "DedeCMS"
  - detection:
      - body: Contains "DedeCMS" or "power by dedecms"
      - path: "/data/admin/ver.txt"
  - default_paths:
      - "/dede/"        # admin login
      - "/member/"
      - "/plus/"
      - "/include/"
      - "/data/"
  - sensitive_paths:
      - "/data/admin/ver.txt"
      - "/data/backupdata/"
      - "/include/common.inc.php"
      - "/install/"
```

### PHPCMS

```yaml
fingerprints:
  - fingerprint: "PHPCMS"
  - detection:
      - body: Contains "phpcms" or "PHPCMS"
      - cookie: "phpcms_auth"
  - default_paths:
      - "/admin.php"
      - "/index.php"
      - "/phpcms/"
  - sensitive_paths:
      - "/caches/"
      - "/install/"
```

### EmpireCMS (帝国CMS)

```yaml
fingerprints:
  - fingerprint: "EmpireCMS"
  - detection:
      - body: Contains "EmpireCMS" or "powered by EmpireCMS"
  - default_paths:
      - "/e/"
      - "/e/admin/"
      - "/e/class/"
      - "/e/data/"
```

### MetInfo (米拓)

```yaml
fingerprints:
  - fingerprint: "MetInfo"
  - detection:
      - body: Contains "MetInfo" or "metinfo"
      - path: "/favicon.ico" hash: specific
  - default_paths:
      - "/admin/"
      - "/app/"
      - "/cache/"
      - "/include/"
```

### ThinkCMF

```yaml
fingerprints:
  - fingerprint: "ThinkCMF"
  - detection:
      - body: Contains "ThinkCMF" or "thinkcmf"
      - cookie: "ThinkCMF"
  - default_paths:
      - "/index.php?m=admin"
      - "/simplewind/"
      - "/data/"
```

### Discuz!

```yaml
fingerprints:
  - fingerprint: "Discuz!"
  - detection:
      - body: Contains "Discuz!" or "Comsenz"
      - cookie: "WQZ9_2132_saltkey"
  - default_paths:
      - "/admin.php"
      - "/forum.php"
      - "/uc_server/"
      - "/api/"
```

### ECshop

```yaml
fingerprints:
  - fingerprint: "ECshop"
  - detection:
      - body: Contains "ECSHOP" or "ecshop"
      - cookie: "ECS_ID"
  - default_paths:
      - "/admin/"
      - "/includes/"
      - "/api/"
```

---

## Chinese Middleware & Infrastructure

### Druid (阿里巴巴数据库连接池)

```yaml
fingerprints:
  - fingerprint: "Druid Monitor"
  - detection:
      - path: "/druid/index.html"
      - body: Contains "Druid Stat"
  - default_paths:
      - "/druid/index.html"
      - "/druid/login.html"
      - "/druid/status.html"
  - sensitive_data:
      - "/druid/websession.html"     # active sessions
      - "/druid/datasource.html"     # DB connection info
      - "/druid/sql.html"            # SQL execution log
      - "/druid/spring.html"         # Spring monitoring
```

### Nacos (阿里巴巴服务发现)

```yaml
fingerprints:
  - fingerprint: "Nacos"
  - detection:
      - path: "/nacos"
      - body: Contains "Nacos"
  - default_paths:
      - "/nacos/"
      - "/nacos/v1/console/server/state"
  - api_endpoints:
      - "GET /nacos/v1/auth/users"           # user list
      - "GET /nacos/v1/console/namespaces"   # namespace list
      - "GET /nacos/v1/cs/configs"           # config list
      - "POST /nacos/v1/cs/configs"           # create config
      - "GET /nacos/v1/ns/service/list"      # service list
```

### Apollo (携程配置中心)

```yaml
fingerprints:
  - fingerprint: "Apollo Config"
  - detection:
      - path: "/apollo"
      - body: Contains "Apollo"
  - default_paths:
      - "/apollo/"
      - "/apollo/config/"
  - api_endpoints:
      - "/apollo/env"
      - "/apollo/configs"
      - "/apollo/apps"
```

### XXL-JOB (分布式调度中心)

```yaml
fingerprints:
  - fingerprint: "XXL-JOB"
  - detection:
      - path: "/xxl-job-admin"
      - body: Contains "XXL-JOB" or "分布式任务调度"
  - default_paths:
      - "/xxl-job-admin/"
      - "/xxl-job-admin/login"
      - "/xxl-job-admin/toLogin"
```

### Skywalking (APM)

```yaml
fingerprints:
  - fingerprint: "Apache Skywalking"
  - detection:
      - path: "/"
      - body: Contains "Skywalking"
  - default_paths:
      - "/graphql"     # GraphQL query endpoint
      - "/logQuery"
```

### RuoYi (若依框架)

```yaml
fingerprints:
  - fingerprint: "RuoYi"
  - detection:
      - body: Contains "ruoyi" or "若依"
      - path: "/ruoyi"
  - default_paths:
      - "/admin/"
      - "/prod-api/"
      - "/common/download/"
  - sensitive_paths:
      - "/prod-api/system/user/list"       # user list
      - "/prod-api/system/config/list"     # config list
```

### JeecgBoot

```yaml
fingerprints:
  - fingerprint: "JeecgBoot"
  - detection:
      - body: Contains "JeecgBoot"
  - default_paths:
      - "/jeecgboot/"
      - "/api/"
  - sensitive_paths:
      - "/api/sys/user/list"
```

---

## Information Disclosure Paths (High Risk)

### Editor Upload Paths

```yaml
FCKEditor:
  - "/FCKeditor/editor/filemanager/connectors/"    # 48% of incidents
  - "/fckeditor/editor/filemanager/upload/"
  - "/FCKeditor/editor/filemanager/browser/default/connectors/"

eWebEditor:
  - "/ewebeditor/"                                    # 28% of incidents
  - "/ewebeditor/admin_login.asp"
  - "/ewebeditor/uploadfile/"

UEditor (百度):
  - "/ueditor/"                                       # 12% of incidents
  - "/ueditor/controller.ashx?action=uploadimage"
  - "/ueditor/php/controller.php?action=uploadfile"

KindEditor:
  - "/kindeditor/"                                    # 8% of incidents
  - "/kindeditor/upload/"
```

### Common Info Disclosure Paths

```yaml
info_disclosure:
  - "/WEB-INF/web.xml"
  - "/WEB-INF/classes/application.properties"
  - "/WEB-INF/classes/application.yml"
  - "/WEB-INF/classes/jdbc.properties"
  - "/WEB-INF/classes/log4j.properties"
  - "/META-INF/context.xml"
  - "/actuator/env"
  - "/actuator/heapdump"
  - "/actuator/beans"
  - "/swagger-ui.html"
  - "/swagger-resources"
  - "/api-docs"
  - "/v2/api-docs"
  - "/v3/api-docs"
  - "/doc.html"
  - "/druid/index.html"
  - "/sitemap.xml"
  - "/robots.txt"
  - "/crossdomain.xml"
  - "/clientaccesspolicy.xml"
  - "/.git/config"
  - "/.svn/entries"
  - "/phpinfo.php"
  - "/info.php"
  - "/test.php"
```

---

## SQL Injection High-Frequency Parameters

Parameters most commonly associated with SQL injection vulnerabilities across disclosed cases:

```yaml
high_risk_params:
  - "id"         # most frequent
  - "categoryid"
  - "type"
  - "page"
  - "classid"
  - "uid"
  - "pid"
  - "gid"
  - "keywords"
  - "search"
  - "title"
  - "name"
  - "sort"
  - "order"
  - "cid"
  - "tid"
  - "mid"
  - "action"
  - "option"
  - "value"
  - "key"
  - "url"
  - "file"
  - "path"
```

---

## Chinese Network Equipment

### Huawei

```yaml
fingerprints:
  - "Huawei Router/Switch"
  - detection:
      - banner: Contains "Huawei" or "Quidway"
      - snmp: ".1.3.6.1.4.1.2011.2.*"
```

### ZTE

```yaml
fingerprints:
  - "ZTE Router/Switch"
  - detection:
      - banner: Contains "ZTE" or "ZXR10"
      - snmp: ".1.3.6.1.4.1.3902.*"
```

### H3C

```yaml
fingerprints:
  - "H3C Network Device"
  - detection:
      - banner: Contains "H3C" or "Comware"
      - snmp: ".1.3.6.1.4.1.25506.*"
```

### Ruijie (锐捷)

```yaml
fingerprints:
  - "Ruijie Network Device"
  - detection:
      - banner: Contains "Ruijie" or "RG-"
      - snmp: ".1.3.6.1.4.1.4881.*"
```

### Sangfor (深信服)

```yaml
fingerprints:
  - "Sangfor SSL VPN/AD"
  - detection:
      - title: Contains "SANGFOR" or "深信服"
      - cookie: "Sangfor"
  - default_paths:
      - "/por/"
      - "/cgi-bin/"
```

---

## Chinese Security Products

### Qi-Anxin (360天擎)

```yaml
fingerprints:
  - fingerprint: "Qi-Anxin Endpoint"
  - detection:
      - body: Contains "360" or "天擎"
      - port: 8080, 8443
```

### DBAPPSecurity (安恒)

```yaml
fingerprints:
  - fingerprint: "DBAPPSecurity"
  - detection:
      - body: Contains "DBAPP" or "明御" or "安恒"
```

### NSFOCUS (绿盟)

```yaml
fingerprints:
  - fingerprint: "NSFOCUS"
  - detection:
      - body: Contains "NSFOCUS" or "绿盟"
```

---

## Chinese Database Products

### Dameng (达梦)

```yaml
fingerprints:
  - fingerprint: "Dameng DB"
  - detection:
      - port: 5236
      - banner: Contains "DAMENG"
```

### KingbaseES (人大金仓)

```yaml
fingerprints:
  - fingerprint: "KingbaseES"
  - detection:
      - port: 54321
      - banner: Contains "Kingbase"
```

### OceanBase (阿里巴巴)

```yaml
fingerprints:
  - fingerprint: "OceanBase"
  - detection:
      - port: 2881, 2883
      - banner: Contains "OceanBase"
```

### TiDB (PingCAP)

```yaml
fingerprints:
  - fingerprint: "TiDB"
  - detection:
      - port: 4000
      - http: 10080 (status dashboard)
```

### GBase (南大通用)

```yaml
fingerprints:
  - fingerprint: "GBase"
  - detection:
      - port: 5258
      - banner: Contains "GBase"
```

### PolarDB (阿里云)

```yaml
fingerprints:
  - fingerprint: "PolarDB"
  - detection:
      - banner: Contains "PolarDB"
      - env: "polardb" in metadata
```

### GoldenDB (中兴)

```yaml
fingerprints:
  - fingerprint: "GoldenDB"
  - detection:
      - port: 3361
      - banner: Contains "GoldenDB"
```

---

## Chinese Surveillance Cameras

### Hikvision (海康威视)

```yaml
fingerprints:
  - fingerprint: "Hikvision Camera / NVR"
  - detection:
      - title: Contains "Hikvision" or "海康"
      - path: "/doc/page/login.asp"
      - port: 80, 8000, 554
  - default_paths:
      - "/doc/page/login.asp"
      - "/ISAPI/Security/userCheck"    # no auth
      - "/onvif/"
```

### Dahua (大华)

```yaml
fingerprints:
  - fingerprint: "Dahua Camera / NVR"
  - detection:
      - title: Contains "Dahua" or "大华"
      - path: "/index.html"
      - port: 80, 37777, 554
```

### Uniview (宇视)

```yaml
fingerprints:
  - fingerprint: "Uniview Camera"
  - detection:
      - title: Contains "Uniview" or "宇视"
      - port: 80, 554
```
