# Tabby 密码解密器

**解密Tabby终端中存储的密码，一键输出明文密码**

支持两种存储方式：
- **Vault加密** - Tabby的自定义加密存储
- **Keytar** - 系统密钥链存储（Windows凭据管理器/macOS钥匙串/Linux libsecret）

---

## 快速开始

```bash
# 创建虚拟环境
python3 -m venv venv
# 激活虚拟环境
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 运行解密器
python tabby_decrypt.py

# 退出虚拟环境（回到系统全局Python）
deactivate

# 删除虚拟环境（想重建环境时）
rm -rf venv

```

---

## 使用方法

### 自动模式（推荐）
```bash
python tabby_decrypt.py
```
自动查找配置文件并检测存储方式，无需任何参数。

### 指定配置文件
```bash
python tabby_decrypt.py "C:\Users\YourName\AppData\Roaming\tabby\config.yaml"
```

### Vault密码短语（命令行输入）
```bash
python tabby_decrypt.py "path\to\config.yaml" "your_vault_passphrase"
```

---

## 输出示例

```
╔══════════════════════════════════════════════════════════╗
║          Tabby 密码解密器 v2.0 - 一体化版                ║
║          支持 Vault + Keytar 两种存储方式                ║
╚══════════════════════════════════════════════════════════╝

[*] 配置文件: C:\Users\Administrator\AppData\Roaming\tabby\config.yaml
[*] 未启用Vault加密，读取系统密钥链...
[*] 正在读取系统密钥链...
[*] 平台: Windows

============================================================
                    Tabby 密码解密结果
============================================================

============================================================
来源: KEYTAR
类型: SSH密码
主机: ssh@192.168.1.100:22
用户: root
密码: MyPassword123

============================================================
来源: KEYTAR
类型: SSH密码
主机: ssh@10.0.0.1:22
用户: admin
密码: Admin@2024

============================================================
统计: SSH密码=24, 私钥密码=0, 文件=0, 总计=24
============================================================
```

---

## 工作原理

### Vault 加密方式

当启用Vault时，Tabby使用以下加密参数：

| 参数 | 值 |
|------|-----|
| 加密算法 | AES-256-CBC |
| 密钥派生 | PBKDF2-HMAC-SHA512 |
| 迭代次数 | 100,000 |
| 盐值长度 | 8 字节 |
| IV长度 | 16 字节（随机） |

### Keytar 存储方式

当未启用Vault时，密码以**明文形式**存储在系统密钥链中：

| 平台 | 存储位置 |
|------|----------|
| Windows | Windows凭据管理器 |
| macOS | 钥匙串访问 |
| Linux | libsecret / KWallet |

**注意**：Keytar存储的密码不需要解密，只需从系统密钥链读取。

---

## 配置文件位置

| 平台 | 路径 |
|------|------|
| Windows | `%APPDATA%\tabby\config.yaml` |
| macOS | `~/Library/Application Support/tabby/config.yaml` |
| Linux | `~/.config/tabby/config.yaml` |

可通过环境变量 `TABBY_CONFIG_DIRECTORY` 自定义路径。

---

## 依赖安装

### 基础依赖（所有平台）
```bash
pip install pyyaml pycryptodome
```

### Windows额外依赖
```bash
pip install pywin32
```

### macOS/Linux
通常无需额外依赖，使用系统自带的security/secret-tool命令。

---

## 常见问题

### Q1: 解密失败，提示"密码短语错误"
检查您输入的Vault密码是否与设置时一致。

### Q2: 提示"未找到任何密码"
可能原因：
- Tabby未保存任何密码
- 密码存储在另一个配置文件中
- 需要管理员权限读取系统密钥链

### Q3: Windows下显示"需要安装pywin32"
```bash
pip install pywin32
```

### Q4: 我不知道用的是Vault还是Keytar？
工具会自动检测，无需担心。直接运行即可。

---

## 技术细节

### Vault存储格式
```yaml
vault:
  version: 1
  contents: base64加密数据
  keySalt: 十六进制盐值
  iv: 十六进制IV
encrypted: true
```

### Keytar存储格式（Windows凭据）
```
目标名称: ssh@192.168.1.1:22/root
用户名: root
密码: 明文密码
```

---

## 安全说明

1. 本工具仅读取本地数据，不上传任何信息
2. 建议在解密后及时清除屏幕输出
3. Keytar存储的密码是明文，建议启用Vault加密
4. 仅用于个人密码恢复，请勿用于非法用途

---

## 源码参考

本工具基于 Tabby 官方源码分析：
- `tabby-core/src/services/vault.service.ts` - Vault加密核心
- `tabby-ssh/src/services/passwordStorage.service.ts` - 密码存储服务

---

## 许可证

MIT License - 仅供学习和授权使用

---

## 更新日志

### v2.0.0 (2026-01-11)
- 合并Vault解密器和Keytar读取器
- 自动检测存储方式
- 一体化工具，无需手动选择

### v1.0.0
- 首次发布
- 分别支持Vault和Keytar
