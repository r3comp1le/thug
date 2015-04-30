from flask import Flask, request, render_template, send_file, redirect, url_for, Response
from functools import wraps
import os, re, urlparse, socket, requests, argparse, sys, yara
import json, zipfile, time, re
from subprocess import call
from time import gmtime, strftime
from pymongo import MongoClient
from ConfigParser import SafeConfigParser
WEB_ROOT = os.path.realpath(os.path.dirname(__file__))
SRC_ROOT =  os.path.abspath(os.path.join(WEB_ROOT, os.pardir))
sys.path.append(SRC_ROOT)
from ThugAPI import *
import logging
log = logging.getLogger("Thug") 
log.setLevel(logging.WARN)

config = SafeConfigParser()
config.read('settings.cfg')

version = "Ver 1.5"


try:
    #User Config
    GEOIP_DOMAIN = config.get('Extra', 'GEOIP_DOMAIN')
    YARA_DIR = config.get('Extra', 'YARA_DIR')

    #Server Config
    svr_ip = config.get('Network', 'ip')
    svr_port = config.getint('Network', 'port')
    svr_debug = config.getboolean('Network', 'debug')
     
except Exception as e:
     print "Kame Config File. Please Check the config file and try again"
     print e
     sys.exit(0)

# create application
app = Flask(__name__)

class MyThug(ThugAPI):
    def __init__(self):
        ThugAPI.__init__(self,None)

def check_auth(username, password):
    #This function is called to check if a username password combination is valid.
	#Not the most secure!!!!!!!, Use a db or file instead
    return username == 'kame' and password == 'kame123'

def authenticate():
    # Sends a 401 response that enables basic auth
    return Response('Login Please', 401,{'WWW-Authenticate': 'Basic realm="Login Required"'})
    
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
    
    
@app.route('/')
@requires_auth
def home():
    return render_template('index.html', version=version)

@app.route('/submit/', methods=['POST'])
@requires_auth
def submit():
    thug = MyThug()
    errors = ''
    url=request.form['url']
    if not url:
        errors = "Please enter a valid URL"
        return render_template('error.html', errors=errors)
    thug.log_init(url)
    
    ua=request.form['UserAgent']
    if not ua:
        ua = 'win7ie80'
    thug.set_useragent(ua)
    
    adobe=request.form['reader']
    if not adobe:
        adobe = '9.1.0'
    thug.set_acropdf_pdf(adobe)
    
    flash=request.form['flash']
    if not flash:
        flash = '10.0.64.0'
    thug.set_shockwave_flash(flash)
    
    java=request.form['java']
    if not java:
        java = '1.6.0.32'
    thug.set_javaplugin(java)
        
    referer=request.form['referer']
    if not referer:
        referer = 'about:blank'
    thug.set_referer(referer)
    
    thetime = str(int(time.time()))
    thedate = strftime("%d %b %Y %H:%M:%S +0000", gmtime())
    
    if not errors:
        url_strip = urlparse.urlparse(url)
        hname = url_strip.hostname
        try:
            ipv4 = socket.gethostbyname(hname)
        except TypeError:
            errors = "Not a valid Hostname"
            return render_template('error.html', errors=errors)
        except NameError:
            errors = "Not a valid Hostname"
            return render_template('error.html', errors=errors)
        except socket.gaierror:
            errors = "Not a valid Hostname"
            return render_template('error.html', errors=errors)
        
        if GEOIP_DOMAIN == "":
            errors = "Please set your GEOIP_DOMAIN server"
            return render_template('error.html', errors=errors)
        
        geo_req = GEOIP_DOMAIN + ipv4
        r = requests.get(geo_req)
        geo_json = r.json()
        geo_country = geo_json['country_name']
        geo_code = geo_json['country_code'].lower()
        
        connection = MongoClient("localhost",27017)
        db = connection.thug.web
        post_records = {"date": thedate,"time":thetime, "url":url, "java":java, "reader":adobe, "flash":flash, "UserAgent":ua, "ip":ipv4, "country":geo_country, "countrycode":geo_code}
        db.insert(post_records)
        connection.close()
        
        reportDIR = os.path.join(WEB_ROOT, "reports", thetime)
        thug.set_log_dir(reportDIR) #-n
        logDIR = os.path.join(WEB_ROOT, "reports", "log.txt")
        thug.set_log_output(logDIR)
        thug.set_file_logging() #-F
        thug.set_json_logging() #-Z
        thug.add_sampleclassifier(YARA_DIR) # -C
        
        #submit
        try:
            #thug.run_remote(url)  API is currently not working
            print 'python thug.py -FZE -u '+ua+' -r '+referer+' -T 300 -n '+reportDIR+' -o '+logDIR+' -A '+adobe+' -S '+flash+' -J '+java+' '+url
            call(["python", "../thug.py", "-FZE", "-u", ua, "-r", referer, "-T", "300", "-n", reportDIR, "-o", logDIR, "-A", adobe, "-S", flash, "-J", java, url])
        except Exception as e:
            errors = "Something went wrong"
            return render_template('error.html', errors=errors)
        status = "Job submitted Successfully."
        
    return render_template('index.html', status=status, thetime=thetime)


@app.route('/results')
@requires_auth
def reports():
    connection = MongoClient("localhost",27017)
    db = connection.thug #DB
    past_reports = db.web.find() #Collection
    connection.close()
    return render_template('results.html', past_reports=past_reports,version=version)
    
@app.route('/settings')
@requires_auth
def settings():
    errors = ''
    server = ''
    port = ''
    geo = ''
    yara = ''
    ipReg = []
    geoReg = []
    yaraReg = []
    portReg = []
    
    try:
        fileOpen = [line.strip() for line in open('settings.cfg')]
    except:
        errors="Config does not exist"
        return render_template('error.html', errors=errors)

    for line in fileOpen:
        if re.search('ip = (.*)', line):
            ipReg = re.search('ip = (.*)', line)
        if re.search('GEOIP_DOMAIN = (.*)', line):
            geoReg = re.search('GEOIP_DOMAIN = (.*)', line)
        if re.search('YARA_DIR = (.*)', line):
            yaraReg = re.search('YARA_DIR = (.*)', line)
        if re.search('port = (.*)', line):
            portReg = re.search('port = (.*)', line)
    
    if ipReg is not None:
        server=ipReg.group(1)
    if portReg is not None:
        port=portReg.group(1)
    if yaraReg is not None:
        yara=yaraReg.group(1)
    if geoReg is not None:
        geo=geoReg.group(1)

    return render_template('settings.html',server=server, port=port,yara=yara,geo=geo,errors=errors,version=version)
    
@app.route('/settingset', methods=['POST'])
@requires_auth
def settingsset():
    try:
        server=request.form['server']
        port=request.form['port']
        geo=request.form['geo']
        yara=request.form['yara']
    except:
        redirect(url_for('settings'))
    
    f = open('settings.cfg','w')
    f.write('[Network]\n')
    f.write('ip = '+server+'\n')
    f.write('port = '+port+'\n')
    f.write('debug = True\n')
    f.write(' \n')
    f.write('[Extra]\n')
    f.write('# https://github.com/fiorix/freegeoip\n')
    f.write('YARA_DIR = '+yara+'\n')
    f.write('GEOIP_DOMAIN = '+geo+'\n')
    f.close()
    redirect 
    return redirect(url_for('settings'))

@app.route('/report/<id>')
@requires_auth
def report(id):
    id = str(id)
    connection = MongoClient("localhost",27017)
    db = connection.thug #DB
    connection.close()
    past_reports = db.web.find({'time':id}) #Collection
    try:
        json_url = os.path.join(WEB_ROOT, "reports/"+id+"/analysis/json", "analysis.json") #Json File
        jsondata = json.load(open(json_url))
    except IOError:
        return render_template('404.html')
    
    url = jsondata["url"]
    referer = jsondata["thug"]["options"]["referer"]
    timestamp = jsondata["timestamp"]
    
    java = jsondata["thug"]["plugins"]["javaplugin"]
    reader = jsondata["thug"]["plugins"]["acropdf"]
    flash = jsondata["thug"]["plugins"]["shockwaveflash"]
    
    behaviors = jsondata["behavior"]
    connections = jsondata["connections"]
    locations = jsondata["locations"]
    code = jsondata["code"]
    
    scan_dir = os.path.join(WEB_ROOT, "reports/"+id)
    yara_report = os.path.join(WEB_ROOT, "reports/"+id, 'yara.json')
    
    if os.path.isfile(yara_report):
        try:
            yara_json = json.load(open(yara_report))
            yara_bool = "success"
            yara_stat = "Yara : Success"
        except ValueError:
            yara_bool = "danger"
            yara_stat = "Yara : Error reading results file"
    else:
        results = []
        rules = yara.compile(YARA_DIR)
        for root, directories, filenames in os.walk(scan_dir):
            for filename in filenames: 
                try:
                    yara_match = rules.match(os.path.join(root,filename))
                    alerts = []
                    for item in yara_match['main']:
                        alert = {}
                        alert['rulename'] = item['rule']
                        strings = []
                        for string in item['strings']:
                            strings.append(string)
                        alert['strings'] = strings
                        alerts.append(alert)
                    if len(yara_match['main']) > 0:
                        file_data = {}
                        file_data['filename'] = filename
                        file_data['alerts'] = alerts
                        results.append(file_data)
                    yara_bool = "warning"
                    yara_stat = "Yara : Refresh Page"
                except Exception as e:
                    yara_bool = "danger"
                    yara_stat = "Yara : Error Running Yara, Refresh Report"
                    print e
                    
        json_results = {}
        json_results['results'] = results
        yara_json=json.dumps(results)
        f = open(yara_report, 'w')
        f.write(yara_json)
        f.close()
                    
    return render_template('report.html', 
        id=id, 
        jsondata=jsondata, 
        past_reports=past_reports, 
        url=url, 
        referer=referer,
        timestamp=timestamp,
        java=java,
        reader=reader,
        flash=flash,
        behaviors=behaviors,
        connections=connections,
        locations=locations,
        code=code,
        yara_bool=yara_bool,
        yara_json=yara_json,
        yara_stat=yara_stat
        )

@app.route("/graph/<id>/graph.svg")
@requires_auth
def getImage(id):
    zip = "reports/"+id+"/analysis/graph.svg"
    return send_file(zip, attachment_filename="graph.svg")
    
@app.route('/download/<id>')
@requires_auth
def download(id):
    files_path = os.path.join("reports", id)  
    zip_file = os.path.join("reports", id+"_package.zip") 

    try:
        zip = zipfile.ZipFile(zip_file, 'w', compression=zipfile.ZIP_DEFLATED)
        root_len = len(os.path.abspath(files_path))
        for root, dirs, files in os.walk(files_path):
            archive_root = os.path.abspath(root)[root_len:]
            for f in files:
                fullpath = os.path.join(root, f)
                archive_name = os.path.join(archive_root, f)
                print f
                zip.write(fullpath, archive_name, zipfile.ZIP_DEFLATED)
        zip.close()
    except IOError:
        return render_template('error.html', errors="Files do not exist")
            
    return send_file(zip_file, attachment_filename="package.zip", as_attachment=True)

@app.errorhandler(404)
@requires_auth
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    #parser = argparse.ArgumentParser()
    #parser.add_argument('-H', '--host', help='Host to bind', default=svr_ip, required=False)
    #parser.add_argument('-p', '--port', help='Port to bind', default=svr_port, required=False, type=int)
    #args = parser.parse_args()

    app.run(host=svr_ip, port=svr_port, debug=svr_debug)