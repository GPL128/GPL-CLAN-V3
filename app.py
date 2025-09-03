import httpx
import time
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import asyncio
from flask import Flask, request, jsonify
from datetime import datetime
import ayadata_pb2
import ayaencode_pb2

# Khởi tạo ứng dụng Flask
app = Flask(__name__)

# Phiên bản Free Fire
freefire_version = "OB50"

# Khóa và IV cho mã hóa AES
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# Biến toàn cục để lưu JWT token
jwt_token = None

# Hàm mã hóa ID
def Encrypt_ID(x):
    x = int(x)
    dec = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
    xxx = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']
    x = x / 128
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return dec[int(m)] + dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return dec[int(n)] + dec[int(z)] + dec[int(y)] + xxx[int(x)]
    return dec[int(x)]  # Thêm trường hợp cơ bản khi x <= 128

# Hàm mã hóa dữ liệu API bằng AES-CBC
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

# Hàm mã hóa ID cho emote
def Encrypt_id_emote(uid):
    result = []
    while uid > 0:
        byte = uid & 0x7F
        uid >>= 7
        if uid > 0:
            byte |= 0x80
        result.append(byte)
    return bytes(result).hex()

# Hàm giải mã ID emote
def Decrypt_id_emote(uidd):
    bytes_value = bytes.fromhex(uidd)
    r, _ = 0, 0
    for byte in bytes_value:
        r |= (byte & 0x7F) << _
        if not (byte & 0x80):
            break
        _ += 7
    return r

# Hàm chuyển đổi timestamp thành định dạng ngày giờ
def convert_timestamp(release_time):
    return datetime.utcfromtimestamp(release_time).strftime('%Y-%m-%d %H:%M:%S')

# Hàm lấy JWT token từ dịch vụ bên ngoài
async def get_jwt_token():
    global jwt_token
    url = "https://obitokenbotvippro.vercel.app/token?uid=3972631254&password=654BF523ECA7CBA017304C1FD5AFC69F65DE6742FF5415FCADD12C8B6BE8A042"
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                if 'token' in data:
                    jwt_token = data['token']
                    print(f"Đã lấy JWT token: {jwt_token}")
                    return {"status": "success", "token": jwt_token}
                else:
                    print("Lỗi: Phản hồi không chứa token")
                    return {"status": "error", "message": "Phản hồi không chứa token"}
            else:
                print(f"Lỗi: Yêu cầu token thất bại với mã trạng thái {response.status_code}")
                return {"status": "error", "message": f"Yêu cầu thất bại với mã trạng thái {response.status_code}"}
        except httpx.RequestError as e:
            print(f"Lỗi yêu cầu khi lấy token: {e}")
            return {"status": "error", "message": f"Lỗi yêu cầu: {str(e)}"}

# Hàm đồng bộ để gọi get_jwt_token
def sync_get_jwt_token():
    return asyncio.run(get_jwt_token())

# Hàm cập nhật token định kỳ
def token_updater():
    while True:
        sync_get_jwt_token()
        time.sleep(8 * 3600)  # Cập nhật mỗi 8 giờ

# Hàm khởi động ứng dụng
def startup():
    sync_get_jwt_token()
    # Chạy token_updater trong một luồng riêng để không chặn ứng dụng
    import threading
    threading.Thread(target=token_updater, daemon=True).start()

# API endpoint để lấy thông tin clan
@app.route("/get_clan_info", methods=["GET"])
def get_clan_info():
    global jwt_token
    clan_id = request.args.get("clan_id")
    if not jwt_token:
        return jsonify({"detail": "JWT token bị thiếu hoặc không hợp lệ"}), 500
    if not clan_id:
        return jsonify({"detail": "Yêu cầu cung cấp Clan ID"}), 400
    
    # Tạo dữ liệu protobuf
    json_data = '''
    {{
        "1": {},
        "2": 1
    }}
    '''.format(clan_id)
    try:
        data_dict = json.loads(json_data)
    except json.JSONDecodeError:
        return jsonify({"detail": "Dữ liệu JSON không hợp lệ"}), 400

    my_data = ayaencode_pb2.MyData()
    my_data.field1 = data_dict["1"]
    my_data.field2 = data_dict["2"]
    
    data_bytes = my_data.SerializeToString()
    padded_data = pad(data_bytes, AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)
    
    url = "https://clientbp.ggblueshark.com/GetClanInfoByClanID"
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": freefire_version,
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": "clientbp.ggblueshark.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }
    
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(url, headers=headers, content=encrypted_data)
    except httpx.RequestError as e:
        return jsonify({"detail": f"Lỗi yêu cầu API: {str(e)}"}), 500
    
    if response.status_code == 200:
        if response.content:
            try:
                response_message = ayadata_pb2.response()
                response_message.ParseFromString(response.content)
                timestamp1_normal = datetime.fromtimestamp(response_message.timestamp1)
                timestamp2_normal = datetime.fromtimestamp(response_message.timestamp2)
                last_active_normal = datetime.fromtimestamp(response_message.last_active)
                return jsonify({
                    "id": response_message.id,
                    "clan_name": response_message.special_code,
                    "timestamp1": timestamp1_normal.strftime("%Y-%m-%d %H:%M:%S"),
                    "value_a": response_message.value_a,
                    "status_code": response_message.status_code,
                    "sub_type": response_message.sub_type,
                    "version": response_message.version,
                    "level": response_message.level,
                    "flags": response_message.flags,
                    "welcome_message": response_message.welcome_message,
                    "region": response_message.region,
                    "json_metadata": response_message.json_metadata,
                    "big_numbers": response_message.big_numbers,
                    "balance": response_message.balance,
                    "score": response_message.score,
                    "upgrades": response_message.upgrades,
                    "achievements": response_message.achievements,
                    "total_playtime": response_message.total_playtime,
                    "energy": response_message.energy,
                    "rank": response_message.rank,
                    "xp": response_message.xp,
                    "timestamp2": timestamp2_normal.strftime("%Y-%m-%d %H:%M:%S"),
                    "error_code": response_message.error_code,
                    "last_active": last_active_normal.strftime("%Y-%m-%d %H:%M:%S"),
                    "guild_details": {
                        "region": response_message.guild_details.region,
                        "clan_id": response_message.guild_details.clan_id,
                        "members_online": response_message.guild_details.members_online,
                        "total_members": response_message.guild_details.total_members,
                        "regional": response_message.guild_details.regional,
                        "reward_time": response_message.guild_details.reward_time,
                        "expire_time": response_message.guild_details.expire_time
                    }
                })
            except Exception as e:
                return jsonify({"detail": f"Lỗi phân tích phản hồi protobuf: {str(e)}"}), 500
        else:
            return jsonify({"detail": "Không có nội dung trong phản hồi"}), 500
    else:
        return jsonify({"detail": f"Lấy dữ liệu thất bại: Mã trạng thái {response.status_code}"}), response.status_code

# Khởi động ứng dụng
if __name__ == "__main__":
    startup()
    app.run(debug=True)