---


---

以下是需要登陆的资产清单，按优先级排序：

---

## 需要登陆的资产

### 🔴 优先级 1 — 已有高危发现，登陆后可深入验证

| 资产                             | 登陆地址                                                                                | 账号类型                               | 备注                                                                    |
| -------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------- | ----------------------------------------------------------------------- |
| **CargoSmart Admin (MCC)** | `https://www.cargosmart.com/admin/login/ul_sign_in.jsf?ENTRY=MCC&ENTRY_TYPE=STANDARD` | CargoSmart MCC 用户账号                | MyFaces反序列化主要攻击面；需先完成滑块验证码                           |
| **MOC Portal (OOCL)**      | `https://moc.oocl.com/admin/login/ul_sign_in.jsf`                                     | OOCL 内部账号                          | WebLogic集群节点!-1825829080；/secured/ API未授权但登陆后可访问更多接口 |
| **CCSC 载体门户**          | `https://www.cargosmart.com/admin/login/ccsc_sign_in.jsf?ENTRY=CCSC`                  | 承运商账号（ANL/MSC/Maersk等任选其一） | 15家承运商入口；jsf_tree_64攻击面与MCC相同                              |

---

### 🟠 优先级 2 — 认证后可发现更多API端点

| 资产                                | 登陆地址                                              | 账号类型                                 | 备注                                                             |
| ----------------------------------- | ----------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------- |
| **OmniOcean**                 | `https://omniocean.cargosmart.com/login`            | CargoSmart 账号                          | 登陆后可访问 /schedule_exchange /exception_monitoring 等业务接口 |
| **Weikayun TMS (Apereo CAS)** | `https://act.weikayun.com/wls_prs_sps/action/login` | 各租户账号（内网IP 172.32.225.181 泄露） | CAS SSO多租户；有 AIR LIQUIDE/BASF/COSCO 等                      |
| **SchedulingSmart**           | `https://www.schedulingsmart.com/login`             | 未知（Istio/BIG-IP后端）                 | 登陆后探索业务API                                                |

---

### 🟡 优先级 3 — Keycloak SSO（登陆后可测试 token/scope）

| 资产                                  | 登陆方式                                                                   | 账号类型           | 备注                                    |
| ------------------------------------- | -------------------------------------------------------------------------- | ------------------ | --------------------------------------- |
| **OOCL 生产 Keycloak**          | `https://exiamfw.home.oocl.com/auth/realms/oocl-prd` password grant      | OOCL 员工账号      | password grant 已启用；可直接 curl 测试 |
| **OOCLlogistics 生产 Keycloak** | `https://iamfw.home.oocllogistics.com/auth/realms/master` password grant | OOCLlogistics 账号 | 同上                                    |
| **Keycloak 非生产 admin**       | `https://exiamfw.home-np.oocl.com/auth/admin/master/console/`            | Keycloak admin     | 已经无认证可访问，登陆后可枚举用户      |

---

### ⚪ 优先级 4 — 辅助资产（完成以上后再考虑）

| 资产                           | 登陆地址                                                                                 | 备注                                      |
| ------------------------------ | ---------------------------------------------------------------------------------------- | ----------------------------------------- |
| **OLL MyPodium**         | `https://demomypodium.oocllogistics.com/mypodium/pub/common/login/cs_up_web_login.jsf` | OLL 内部用户；RichFaces攻击面             |
| **FreightSmart**         | `https://freightsmart.oocl.com/en/`                                                    | OOCL Keycloak SSO，需OOCL账号             |
| **TOSC UAT (supplier)**  | `https://tosc-uat.supplier.digital.oocl.com/login`                                     | 供应商账号；CORS `*` + DELETE方法已确认 |
| **cnrtest.weikayun.com** | `https://cnrtest.weikayun.com`                                                         | LERA测试系统；Kong 3.6.1后端              |

---

 **登陆步骤** ：请通过 Burp 代理完成登陆，成功后将 Cookie/Token 写入 `auth_sessions` 表，格式：

```bash
python3 TOOLS/db_query.py --target "货讯通科技" \
  "INSERT INTO auth_sessions (token_name, token_value, domain, is_active) VALUES ('JSESSIONID', '<value>', 'www.cargosmart.com', 1)" \
  --write
```
