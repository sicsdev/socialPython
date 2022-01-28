
import urllib.request
from tqdm import tqdm
from urllib import request
import random,sys,time,uuid,warnings,os,hashlib,requests,gzip,json,string
from bs4 import BeautifulSoup
warnings.filterwarnings("ignore")
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)
CORS(app, resources={r"*": {"origins": "*"}})


def get_app_path():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
    else:
        try:
            app_full_path = os.path.realpath(__file__)
            application_path = os.path.dirname(app_full_path)
        except NameError:
            application_path = application_path
    return application_path

byteTable1= "D6 28 3B 71 70 76 BE 1B A4 FE 19 57 5E 6C BC 21 B2 14 37 7D 8C A2 FA 67 55 6A 95 E3 FA 67 78 ED 8E 55 33 89 A8 CE 36 B3 5C D6 B2 6F 96 C4 34 B9 6A EC 34 95 C4 FA 72 FF B8 42 8D FB EC 70 F0 85 46 D8 B2 A1 E0 CE AE 4B 7D AE A4 87 CE E3 AC 51 55 C4 36 AD FC C4 EA 97 70 6A 85 37 6A C8 68 FA FE B0 33 B9 67 7E CE E3 CC 86 D6 9F 76 74 89 E9 DA 9C 78 C5 95 AA B0 34 B3 F2 7D B2 A2 ED E0 B5 B6 88 95 D1 51 D6 9E 7D D1 C8 F9 B7 70 CC 9C B6 92 C5 FA DD 9F 28 DA C7 E0 CA 95 B2 DA 34 97 CE 74 FA 37 E9 7D C4 A2 37 FB FA F1 CF AA 89 7D 55 AE 87 BC F5 E9 6A C4 68 C7 FA 76 85 14 D0 D0 E5 CE FF 19 D6 E5 D6 CC F1 F4 6C E9 E7 89 B2 B7 AE 28 89 BE 5E DC 87 6C F7 51 F2 67 78 AE B3 4B A2 B3 21 3B 55 F8 B3 76 B2 CF B3 B3 FF B3 5E 71 7D FA FC FF A8 7D FE D8 9C 1B C4 6A F9 88 B5 E5"

def getXGon(url,stub,cookies):
    NULL_MD5_STRING = "00000000000000000000000000000000"
    sb=""
    if len(url)<1 :
        sb =NULL_MD5_STRING
    else:
        sb =encryption(url)
    if len(stub)<1:
        sb+=NULL_MD5_STRING
    else:
        sb+=stub
    if len(cookies)<1:
        sb+=NULL_MD5_STRING
    else:
        sb+=encryption(cookies)
    index = cookies.index("sessionid=")
    if index == -1:
        sb+=NULL_MD5_STRING
    else:
        sessionid = cookies[index+10:]
        if sessionid.__contains__(';'):
            endIndex = sessionid.index(';')
            sessionid = sessionid[:endIndex]
        sb+=encryption(sessionid)
    return sb

def encryption(url):
    obj = hashlib.md5() 
    obj.update(url.encode("UTF-8"))
    secret = obj.hexdigest()
    return secret.lower()

def initialize(data):
    myhex = 0
    byteTable2 = byteTable1.split(" ")
    for i in range(len(data)):
        hex1 = 0
        if i==0:
            hex1= int(byteTable2[int(byteTable2[0],16)-1],16)
            byteTable2[i]=hex(hex1)
            # byteTable2[i] = Integer.toHexString(hex1);
        elif i==1:
            temp=   int("D6",16)+int("28",16)
            if temp>256:
                temp-=256
            hex1 = int(byteTable2[temp-1],16)
            myhex = temp
            byteTable2[i] = hex(hex1)
        else:
            temp = myhex+int(byteTable2[i], 16)
            if temp > 256:
                temp -= 256
            hex1 = int(byteTable2[temp - 1], 16)
            myhex = temp
            byteTable2[i] = hex(hex1)
        if hex1*2>256:
            hex1 = hex1*2 - 256
        else:
            hex1 = hex1*2
        hex2 = byteTable2[hex1 - 1]
        result = int(hex2,16)^int(data[i],16)
        data[i] = hex(result)
    for i in range(len(data)):
        data[i] = data[i].replace("0x", "")
    return data

def handle(data):
    for i in range(len(data)):
        byte1 = data[i]
        if len(byte1)<2:
            byte1+='0'
        else:
            byte1 = data[i][1] +data[i][0]
        if i<len(data)-1:
            byte1 = hex(int(byte1,16)^int(data[i+1],16)).replace("0x","")
        else:
            byte1 = hex(int(byte1, 16) ^ int(data[0], 16)).replace("0x","")
        byte1 = byte1.replace("0x","")
        a =  (int(byte1, 16) & int("AA", 16)) / 2
        a = int(abs(a))
        byte2 =((int(byte1,16)&int("55",16))*2)|a
        byte2 = ((byte2&int("33",16))*4)|(int)((byte2&int("cc",16))/4)
        byte3 = hex(byte2).replace("0x","")
        if len(byte3)>1:
            byte3 = byte3[1] +byte3[0]
        else:
            byte3+="0"
        byte4 = int(byte3,16)^int("FF",16);
        byte4 = byte4 ^ int("14",16)
        data[i] = hex(byte4).replace("0x","")
    return data

def xGorgon(timeMillis,inputBytes):
    data1 = []
    data1.append("3")
    data1.append("61")
    data1.append("41")
    data1.append("10")
    data1.append("80")
    data1.append("0")
    data2 = input1(timeMillis,inputBytes)
    data2 = initialize(data2)
    data2 = handle(data2)
    for i in range(len(data2)):
        data1.append(data2[i])

    xGorgonStr = ""
    for i in range(len(data1)):
        temp = data1[i]+""
        if len(temp)>1:
            xGorgonStr += temp
        else:
            xGorgonStr +="0"
            xGorgonStr+=temp
    return xGorgonStr


def input1(timeMillis,inputBytes):
    result = []
    for i in range(4):
        if inputBytes[i]<0:
            temp = hex(inputBytes[i])+''
            temp = temp[6:]
            result.append(temp)
        else:
            temp = hex(inputBytes[i]) + ''
            result.append(temp)
    for i in range(4):
        result.append("0")
    for  i in range(4):
        if inputBytes[i+32]<0:
            result.append( hex(inputBytes[i+32])+'')[6:]
        else:
            result.append(hex(inputBytes[i + 32]) + '')
    for i in range(4):
        result.append("0")
    tempByte = hex(int(timeMillis))+""
    tempByte = tempByte.replace("0x","")
    for i in range(4):
        a = tempByte[i * 2:2 * i + 2]
        result.append(tempByte[i*2:2*i+2])
    for i in range(len(result)):
        result[i] = result[i].replace("0x","")
    return result

def strToByte(str):
    length = len(str)
    str2 = str
    bArr =[]
    i=0
    while i < length:
        # bArr[i/2] = b'\xff\xff\xff'+(str2hex(str2[i]) << 4+str2hex(str2[i+1])).to_bytes(1, "big")
        a = str2[i]
        b = str2[1+i]
        c = ((str2hex(a) << 4)+str2hex(b))
        bArr.append(c)
        i+=2
    return bArr

def str2hex(s):
    odata = 0;
    su =s.upper()
    for c in su:
        tmp=ord(c)
        if tmp <= ord('9') :
            odata = odata << 4
            odata += tmp - ord('0')
        elif ord('A') <= tmp <= ord('F'):
            odata = odata << 4
            odata += tmp - ord('A') + 10
    return odata

def doGetGzip(url,headers,charset):
    req = request.Request(url)
    for key in headers:
        req.add_header(key,headers[key])
    # print(req)
    with request.urlopen(req) as f:
        data = f.read()
        return gzip.decompress(data).decode()

def random_sleep(start=3,end=7):
    rt = random.randint(start,end)
    time.sleep(rt)

class Scrapper:
    
    
    def __init__(self,cookie):
        self.session = None
        self.cookie = cookie
        

    def load_session(self):
        if not self.session:
            self.session = requests.session()
            self.session.headers = {
                "X-Gorgon":'',
                "X-Khronos": '',
                "sdk-version":"1",
                "Accept-Encoding": "gzip",
                "x-xx-req-ticket": '',
                "User-Agent": "okhttp/3.12.1",
                "Cookie": self.cookie,
                "Connection": "Keep-Alive",
                "x-tt-token":"03446c738a02fbfa169a7a25faa07ba4fb056c52a8b73183c8893d1412278ee959f7cf18a57c49bd1659fb8d0f8445c58af19ffeda2d25a34570bbc7172f9b9a297541cda408daac4e36f2ecb7f80963729ed-1.0.0"
            }

    def update_headers(self,url=None):
        self.load_session()
        cuurentTimeStamp = str(time.time()).split(".")[0]
        _rticket =str(time.time()*1000).split(".")[0]
        if url:params = url[url.index('?')+1:]
        s = getXGon(params,"",self.cookie)
        gorgon = xGorgon(cuurentTimeStamp,strToByte(s))
        self.session.headers.update({
            'X-Gorgon': gorgon,
            'X-Khronos': cuurentTimeStamp,
            "x-xx-req-ticket": _rticket,
        })

    def get_rticket(self):
        return str(time.time()*1000).split(".")[0]

    def get_current_timestamp(self):
        return str(time.time()).split(".")[0]

    def get_profile_attributes(self,target_username):       # return log_pb, impr_id, sec_uid, uid etc
        self.load_session()
        try:
            endpoint = "https://api16-normal-c-alisg.tiktokv.com/aweme/v1/user/uniqueid/?id={}&retry_type=no_retry&iid=6990986075587151621&device_id=6979528049433036293&ac=wifi&channel=googleplay&aid=1233&app_name=musical_ly&version_code=130603&version_name=13.6.3&device_platform=android&ab_version=13.6.3&ssmix=a&device_type=G011A&device_brand=google&language=en&os_api=25&os_version=7.1.2&uuid=010119606495071&openudid=ccbf98488542a70e&manifest_version_code=2021306030&resolution=720*1280&dpi=240&update_version_code=2021306030&_rticket={}&current_region=US&app_type=normal&sys_region=US&is_my_cn=0&pass-route=1&mcc_mnc=31070&pass-region=1&timezone_name=Asia%2FShanghai&residence=US&ts=1627718992&timezone_offset=28800&build_number=13.6.3&region=en&uoo=0&app_language=en&carrier_region=US&locale=en&ac2=wifi"
            _rticket = self.get_rticket()
            self.update_headers(url=endpoint.format(target_username,_rticket))
            url = endpoint.format(target_username,_rticket)
            res = self.session.get(url)
            return res.json()
        except Exception as e:
            print(e)
            return {"Exception": str(e)}

    def get_post_from_url(self,target_post_url):

        if "vm." in target_post_url:
            headers1={"user-agent":"Dalvik/2.1.0 (Linux; U; Android 7.1.2; G011A Build/N2G48H)"}
            ree=requests.get(target_post_url,headers=headers1,allow_redirects=False)
            print(ree.content)
            soup = BeautifulSoup(ree.text, 'html.parser')
            cc=soup.find(href=True)
            lin=(cc['href']).split("&")
        
            for i in lin:
                if "share_item_id" in i:
                    post_id=((i.split("="))[1])
                    print(post_id)

        else:           
            c=(target_post_url.split("/"))
            d=(c[-1].split("?"))
            post_id=((d[0].split("-"))[-1]).replace(".html","")
            # if post_id=="":
            #     post_id=(target_post_url.split("/"))[-1]
            #     print("post_id",post_id)
            print(post_id)
        self.load_session()

        endpoint="https://api22-normal-c-useast2a.tiktokv.com/aweme/v1/aweme/detail/?aweme_id={}&origin_type&request_source=0&notice_source=0&translator_id&iid=7054221028113336091&device_id=7021240092987835909&ac=wifi&channel=googleplay&aid=1233&app_name=musical_ly&version_code=220804&version_name=22.8.4&device_platform=android&ab_version=22.8.4&ssmix=a&device_type=G011A&device_brand=google&language=en&os_api=25&os_version=7.1.2&openudid=5f150d1b5cd4fc3d&manifest_version_code=2022208040&resolution=720*1280&dpi=240&update_version_code=2022208040&_rticket={}&current_region=US&app_type=normal&sys_region=US&mcc_mnc=31004&timezone_name=Asia%2FShanghai&residence=US&ts={}&timezone_offset=28800&build_number=22.8.4&region=US&uoo=0&app_language=en&carrier_region=US&locale=en&op_region=US&ac2=wifi&host_abi=x86&cdid=178bbcd5-9d5c-4192-92e6-5437d136f5af"
        _rticket = self.get_rticket()
        timestamp=self.get_current_timestamp()
        url = endpoint.format(post_id,_rticket,timestamp)
        self.update_headers(url=url)
        res = self.session.get(url)
        data = res.json()["aweme_detail"]
        # v=json.dumps(data,indent=2)

        # with open("c.json","w+") as ee:
        #     ee.write(v)

        post1={ 
                "username": data["author"]["unique_id"],
                "post_id": data['aweme_id'],
                "caption": data['desc'],
                
                "video_url": data["video"]["play_addr"]["url_list"],
                "cover":data["video"]["cover"]['url_list']
        }
        print(post1)
        urlpath=os.path.join(get_app_path(),"urls.txt")
        with open(urlpath,"a+",encoding="utf8") as qw:
        
            qw.write(str(post1)+"\n")


    def get_user_posts(self,target_username,limit):
     
        self.load_session()
        user_attributes = self.get_profile_attributes(target_username)
        sec_uid = user_attributes.get('sec_uid')
        print(sec_uid)

        endpoint="https://{}/aweme/v1/aweme/post/?source=0&user_avatar_shrink=96_96&video_cover_shrink=248_330&max_cursor={}&sec_user_id={}&count=20&ac=wifi&channel=googleplay&aid=1233&app_name=musical_ly&version_code=220804&version_name=22.8.4&device_platform=android&ab_version=22.8.4&ssmix=a&device_type=G011A&device_brand=google&language=en&os_api=25&os_version=7.1.2&openudid=5f150d1b5cd4fc3d&manifest_version_code=2022208040&resolution=720*1280&dpi=240&update_version_code=2022208040&_rticket={}&current_region=US&app_type=normal&sys_region=US&mcc_mnc=31004&timezone_name=Asia%2FShanghai&residence=US&ts={}&timezone_offset=28800&build_number=22.8.4&region=US&uoo=0&app_language=en&carrier_region=US&locale=en&op_region=US&ac2=wifi&host_abi=x86&cdid=178bbcd5-9d5c-4192-92e6-5437d136f5af"
        # endpoint="https://{}/aweme/v1/aweme/post/?source=0&user_avatar_shrink=96_96&video_cover_shrink=248_330&max_cursor={}&sec_user_id={}&count=20&iid={}&device_id={}&ac=wifi  &channel=googleplay&aid=1233&app_name=musical_ly&version_code=220804&version_name=22.8.4&device_platform=android&ab_version=22.8.4&ssmix=a&device_type=G011A&device_brand=google&language=en&os_api=25&os_version=7.1.2&openudid=5f150d1b5cd4fc3d&manifest_version_code=2022208040&resolution=720*1280&dpi=240&update_version_code=2022208040&_rticket={}&current_region=US&app_type=normal&sys_region=US&mcc_mnc=31004&timezone_name=Asia%2FShanghai&residence=US&ts={}&timezone_offset=28800&build_number=22.8.4&region=US&uoo=0&app_language=en&carrier_region=US&locale=en&op_region=US&ac2=wifi&host_abi=x86&cdid=178bbcd5-9d5c-4192-92e6-5437d136f5af"
        DATA = []
        offset = 0
        max_cursor = 0
        total = None
        pb = tqdm(total=limit)
        count=0
        iid=6990986075587151622
        did=6979528049433036294
        endp=[
            "api19-normal-c-useast2a.tiktokv.com",
            "api19-normal-c-useast1a.tiktokv.com",
            "api16-normal-c-useast2a.tiktokv.com",
            "api16-normal-c-useast1a.tiktokv.com",
            "api16-normal-c-alisg.tiktokv.com",
            "api16-core-c-alisg.tiktokv.com",
            "api19-core-c-useast2a.tiktokv.com",
            "api19-core-c-useast1a.tiktokv.com",
            "api16-core-c-useast2a.tiktokv.com",
            "api16-core-c-useast1a.tiktokv.com",
            "api22-normal-c-alisg.tiktokv.com",
            "api22-normal-c-useast2a.tiktokv.com",
            "api22-normal-c-useast1a.tiktokv.com",
            "api22-core-c-alisg.tiktokv.com",
            "api22-core-c-useast2a.tiktokv.com",
            "api22-core-c-useast1a.tiktokv.com",
            "api21-core-c-alisg.tiktokv.com",
            "api31-normal-c-alisg.tiktokv.com"
                    ]
    
        ew=random.choice(endp)
        # iid=7036627286820600000+random.randint(1000,9000)
        # did=6906478625937270000+random.randint(1000,9000)
        try:
            while len(DATA) < limit:
                _rticket = self.get_rticket()
                timestamp=self.get_current_timestamp()
               
                url = endpoint.format(ew,str(max_cursor),sec_uid,_rticket,timestamp)
                # print(url)
                self.update_headers(url=url)
                res = self.session.get(url)
                try:

                    data = res.json()
                except Exception as e:
                    print(e)
                    ew=random.choice(endp)

                    # iid=7036627286820600000+random.randint(1000,9000)
                    # did=6906478625937270000+random.randint(1000,9000)
                    continue
                    
                v=json.dumps(data,indent=2)

                # with open("c.json","w+") as ee:
                #     ee.write(v)

                for dat in data.get('aweme_list'):

                    # save=os.path.join(get_app_path(),"downloaded.txt")
                    # sa=[line.rstrip() for line in open(save)]

                    # if dat['aweme_id'] in sa:
                    #     print("Already Downloaded")
                    #     continue
                    # # else:
                    # count+=1
                    # print(count)

                    post1={ 
                            "username": dat["author"]["unique_id"],
                            "post_id": dat['aweme_id'],
                            "caption": dat['desc'],
                            "video_url": dat["video"]["play_addr"]["url_list"],
                            "cover":dat["video"]["cover"]['url_list']
                        }
                    # print(post1)
                    # urlpath=os.path.join(get_app_path(),"urls.txt")
                    # with open(urlpath,"a+",encoding="utf8") as qw:
                    
                    #     qw.write(str(post1)+"\n")
                    # if download(post1,"user"):
                    #     print(count, "posts downloaded of user {} \n".format(dat["author"]["unique_id"]))

                    # pb.update(n=len(data.get('aweme_list')))
                    DATA.append(post1)
                # DATA += data.get('aweme_list')
                pb.update(n=len(data.get('aweme_list')))
                offset += 20
                if data.get('has_more') is False: break
                # random_sleep()
                max_cursor = data.get("max_cursor")
            pb.close()
        except Exception as e:
            print(e)
            return {"Exception": str(e)}

        return DATA
   
@app.route('/api/tiktok-videos', methods=['POST'])
def testpost():
    input_json = request.get_json(force=True)
    username = input_json['username']

    eq="sessionid="+uuid.uuid4().hex.lower()[0:32]
    sc = Scrapper(eq)
    posts=sc.get_user_posts(username,30)
    return jsonify({"success": "true", "videos": posts})
