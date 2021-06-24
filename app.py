from flask_login import login_user, login_required, logout_user, current_user
from flask import render_template, request, redirect, jsonify
from datetime import timedelta, datetime
import random
import string
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_login import LoginManager
from flask_wtf import CSRFProtect, Recaptcha
import hashlib
from sqlalchemy import *
from sqlalchemy.orm import relationship
from flask_admin.contrib.sqla import  ModelView
from flask_login import UserMixin



# File Init
app = Flask(__name__)
app.secret_key = "adsflkjqoijqawsef0asiodjf9028344jfoasijfpoajsdlkfjaso9fj390asdofjasdoijflasdkjfo"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://loozzike_webkey:pL22RKzRGzNo5xi@103.97.125.252/loozzike_webkey?charset=utf8mb4"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config['JSON_AS_ASCII'] = False

app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']= 'enter_your_public_key'
app.config['RECAPTCHA_PRIVATE_KEY']='enter_your_private_key'
app.config['RECAPTCHA_OPTIONS'] = {'theme':'white'}


csrf = CSRFProtect()
csrf.init_app(app=app)

db = SQLAlchemy(app=app)


admin= Admin(app=app,  name="Quan Ly Web", template_mode="bootstrap3")

login = LoginManager()
login.init_app(app)


def str_to_md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def random_str(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))



# File model 


class User(db.Model, UserMixin):
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(50), nullable=True, default="")
    username = Column(String(50), nullable=False)
    password = Column(Text, nullable=False)
    coin = Column(BigInteger, default=10)
    coin_used = Column(BigInteger, default=0)
    ref_key = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True)
    type = Column(String(30), default="member")
    list_key = relationship("ListKey", backref="user", lazy=True)

    def __str__(self):
        return self.username

class ListKey(db.Model):
    __tablename__ = "listkey"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    key_value = Column(Text, nullable=False)
    date_active = Column(DateTime, nullable=False)
    date_expired = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    change_limit = Column(Integer, default=0)
    amount_changed = Column(Integer, default=0)
    giver = Column(String(50), default="")

    def __str__(self):
        return self.key_value

class HistoryChangeKey(db.Model):
    __tablename__ = "changekey_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    key_value = Column(Text, nullable=False)
    key_old = Column(Text, nullable=False)
    date_changed = Column(DateTime, nullable=False)

class HistoryRecharge(db.Model):
    __tablename__ = "recharce_history"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    denominations = Column(BigInteger, nullable=False)
    service = Column(String(50), nullable=False)
    date_request = Column(DateTime, nullable=False)
    date_accept = Column(DateTime, nullable=True)
    accepted = Column(Boolean, nullable=True)
    notes = Column(Text, default="" , nullable=True)
    random_key = Column(String(50), nullable=True, default="")

class RechargeRequest(db.Model):
    __tablename__ = "recharge_request"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey(User.id), nullable=False)
    denominations = Column(BigInteger, nullable=False)
    service = Column(String(50), nullable=False)
    date_request = Column(DateTime, nullable=False)
    accepted = Column(Boolean, nullable=True)
    random_key = Column(String(50), nullable=True, default="")



# Ke thua lai
class HistoryModelView(ModelView):
    can_create = False
    can_edit = False
    can_delete = False



# if __name__ == "__main__":
#     db.create_all()

admin.add_view(HistoryModelView(User, db.session))
admin.add_view(HistoryModelView(ListKey, db.session))
admin.add_view(HistoryModelView(HistoryChangeKey, db.session))
admin.add_view(HistoryModelView(HistoryRecharge, db.session))
admin.add_view(HistoryModelView(RechargeRequest, db.session))


# File Main


@login.user_loader
def user_load(user_id):
    return User.query.get(user_id)

@app.route('/admin')
def admin():
    if current_user.is_authenticated:
        return render_template('admin/index.html')
    else:
        return redirect('/')


@app.route('/nap-tien', methods=["GET", "POST"])
def naptien():
    if request.method == "GET":
        return render_template('nap-tien.html', random_str=random_str())
    else:
        try:
            giatri = int(request.form.get('denominations', ''))
        except:
            return jsonify({"log":"Lỗi rồiiiiiiiiiiiiiii"})
        service = request.form.get('service', '')
        content = request.form.get('content', '')
        try:
            yeuCauNapTien = RechargeRequest()
            yeuCauNapTien.user_id = current_user.id
            yeuCauNapTien.service = service
            yeuCauNapTien.date_request = datetime.now()
            yeuCauNapTien.denominations = giatri
            yeuCauNapTien.random_key = content

            yc = HistoryRecharge()
            yc.user_id = current_user.id
            yc.denominations = giatri
            yc.date_request = datetime.now()
            yc.service = service
            yc.random_key = content

            db.session.add(yc)
            db.session.add(yeuCauNapTien)
            db.session.commit()
            return jsonify({'log':'Thành công! Vui lòng chờ admin xử lí.....'})
        except:
            return jsonify({'log':'Lỗi....'})


@app.route('/duyet', methods=["POST", "GET"])
def duyet():
    if request.method == "GET":
        if current_user.type == "admin":
            return render_template('/naptien.html', data=RechargeRequest.query.all())
        else:
            return "Vjp zay, biet vao day luon 😲😲😲"
    else:
        accepted = request.form.get('accepted', '')
        user_id = request.form.get('user_id')
        key = request.form.get('key')
        notes = request.form.get('notes', '')
        h = HistoryRecharge.query.filter(HistoryRecharge.random_key == key, HistoryRecharge.user_id == user_id).first()
        h.notes = notes
        h.date_accept = datetime.now()
        k = RechargeRequest.query.filter(RechargeRequest.random_key == key, RechargeRequest.user_id == user_id).first()
        u = User.query.filter(User.id == user_id).first()
        if accepted == '1':
            h.accepted = True
            k.accepted = True
            u.coin += k.denominations
        elif accepted == '0':
            h.accepted = False
            k.accepted = False
        else:
            return jsonify({'log':'dcmm'})

        db.session.commit()
        return jsonify({'log':'OK'})


@app.route('/refresh')
def kiem_tra_key():
    for key in ListKey.query.all():
        if key.date_expired >= datetime.now():
            key.is_active = False



@app.route('/info', methods=["GET", "POST"])
def info():
    if current_user.is_authenticated:
        if request.method == "POST":
            email = request.form.get('email').strip()
            password = request.form.get('password', '').strip()
            new_password = request.form.get('new_password','').strip()
            if str_to_md5(password) == current_user.password:
                current_user.email = email
                if len(new_password) > 0:
                    current_user.password = str_to_md5(new_password)
                db.session.commit()
                return jsonify({"log":"Thành công!"})
            else:
                return jsonify({"log":"Mật khẩu không chính xác!"})
        else:
            return render_template('info.html', data=ListKey.query.filter(ListKey.user_id == current_user.id), history_recharge=HistoryRecharge.query.filter(HistoryRecharge.user_id == current_user.id))

    else:
        return redirect('/')


@app.route("/buykey", methods=['POST', "GET"])
@login_required
def buykey():
    if request.method == "POST":
        key_machine = request.form.get('mamay', '').strip()
        option = request.form.get('options')

        if current_user.coin >= int(option[0:2]) * 1000:
            check_key = ListKey.query.filter(ListKey.user_id == current_user.id, ListKey.key_value == key_machine).first()
            if not check_key:
                try:
                    k = ListKey()
                    k.user_id = current_user.id
                    k.key_value = key_machine
                    k.date_active = datetime.now()
                    k.date_expired = datetime.now() + timedelta(days=30)
                    if option == '30k':
                        k.change_limit = 3
                    elif option == '40k':
                        k.change_limit = 5
                    else:
                        k.change_limit = 10
                    current_user.coin -= int(option[0:2])*1000
                    current_user.coin_used += int(option[0:2])*1000
                    db.session.add(k)
                    db.session.commit()
                    return jsonify({"log": "Kích hoạt mã máy thành công!"})

                except:
                    return jsonify({"log":"Có lỗi trong quá trình kích hoạt, vui lòng thử lại~~~"})
            else:
                k = ListKey.query.filter(ListKey.key_value == key_machine).first()
                k.date_expired += timedelta(days=30)
                if k.date_expired > datetime.now():
                    k.is_active = True
                if option == '30k':
                    k.change_limit += 3
                elif option == '40k':
                    k.change_limit += 5
                else:
                    k.change_limit += 10
                current_user.coin -= int(option[0:2]) * 1000
                current_user.coin_used += int(option[0:2]) * 1000
                db.session.commit()
                return jsonify({"log": "Gia hạn thành công!"})
        else:
            return jsonify({"log": "Số dư không đủ, vui lòng thử lại~~"})
    else:
        return jsonify({"log": "Chao Xìn, vui lòng thử lại~~~"})


@app.route("/check", methods=["GET", "POST"])
def check():
    if request.method == "POST":
        key_machine = request.form.get('mamay', "").strip()
        k = ListKey.query.filter(ListKey.key_value == key_machine).first()
        if k:
            s = {"key_value": k.key_value,
                 "date_active": k.date_active.strftime("%d/%m/%Y"),
                 "date_expired": k.date_expired.strftime("%d/%m/%Y"),
                 "count": k.change_limit - k.amount_changed,
                 "status": k.is_active
            }
            return jsonify({"log":"Thành công", "data": s})
        else:
            return jsonify({"log":"Mã máy không tồn tại, vui lòng thử lại~"})
    else:
        return jsonify({"log":"Xin chào, vui lòng thử lại :>"})


@app.route("/change", methods=["GET", "POST"])
def change():
    if request.method == "POST":
        key_old = request.form.get('mamay_cu').strip()
        key_new = request.form.get('mamay_moi').strip()
        check_key = ListKey.query.filter(ListKey.user_id == current_user.id, ListKey.key_value == key_old).first()
        if check_key:
            if check_key.change_limit - check_key.amount_changed > 0:
                check_key.key_value = key_new
                check_key.amount_changed += 1
                htr = HistoryChangeKey()
                htr.user_id = current_user.id
                htr.key_value = key_new
                htr.key_old = key_old
                htr.date_changed = datetime.now()
                db.session.add(htr)
                db.session.commit()
                return jsonify({"log":"Success", "remain": check_key.change_limit - check_key.amount_changed})
            else:
                return jsonify({"log":"Số lượt đổi đã hết~~"})
        else:
            return jsonify({"log": "Mã máy chưa từng được kích hoạt~~"})
    return jsonify({"log":"ahihi"})


@app.route("/transfer", methods=["POST", "GET"])
def transfer():
    if request.method == "POST":
        key_old = request.form.get('mamay_cu')
        key_new = request.form.get('mamay_moi')
        username = request.form.get('username_nhan')
        if username == current_user.username:
            return jsonify({"log":"Không thể tặng cho chính mình!!!"})
        k = ListKey.query.filter(ListKey.user_id == current_user.id, ListKey.key_value == key_old).first()
        u = User.query.filter(User.username == username).first()
        if u:
            if k:
                check = ListKey.query.filter(ListKey.user_id == u.id, ListKey.key_value == key_new).first()
                if not check:
                    k.key_value = key_new
                    k.user_id = u.id
                    k.giver = current_user.username
                    db.session.commit()
                    return jsonify({'log':'Thành công!!!'})
                else:
                    return jsonify({'log':'Tài khoản này đã kích hoạt mã máy này rồi, vui lòng thử mã khác 👌'})
            else:
                return jsonify({"log":"Mã máy chưa được kích hoạt!!!"})
        else:
            return jsonify({'log':'Tài khoản nhận không hợp lệ!!'})


    return jsonify({"log":"ahihi do ngoc"})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password', '')
        password = str_to_md5(password)
        user = User.query.filter(User.username == username,
                                 User.password == password
                                 ).first()
        if user:
            login_user(user=user)
        else:
            return render_template("login.html", wr='false')
    return redirect('/')


@app.route('/register', methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip()
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        re_password = request.form.get('re-password').strip()
        ref_key = request.form.get('ref-key', '')
        if len(username) < 6:
            return render_template("login.html", ct = "Tài khoản phải có từ 6 chữ số trở lên!!!")
        if password != re_password:
            return render_template("login.html", ct = 'Mật khẩu không trùng nhau!')
        if len(password) < 6:
            return render_template("login.html", ct = 'Mật khẩu phải từ 6 kí tự trở lên...')
        user  = User.query.filter(User.username == username).first()
        if user:
            return render_template("login.html", ct = "Tài khoản đã tồn tại, vui lòng thử bằng tên đăng nhập khác~!")

        user = User()
        user.email = email
        user.username = username
        user.password = str_to_md5(password)
        user.ref_key = ref_key
        db.session.add(user)
        db.session.commit()

        user = User.query.filter(User.username == username, User.password == str_to_md5(password)).first()
        login_user(user)

    return redirect('/')


@app.route("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
    return redirect('/')


@app.route("/")
def index():
    if current_user.is_authenticated:
        return render_template("index.html")
    else:
        return render_template("login.html")


if __name__ == "__main__":
    app.run()