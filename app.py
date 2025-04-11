from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from captcha.image import ImageCaptcha
import random, string
app = Flask(__name__)
app.secret_key = 'çokgizlibirşey'
UPLOAD_FOLDER = 'static/pdfs'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/admin/upload-pdf', methods=['GET', 'POST'])
def upload_pdf():
    if 'admin' not in session:
        return redirect('/admin/login')

    message = ""
    if request.method == 'POST':
        title = request.form['title']
        cefr_level = request.form['cefr_level']
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO pdf_topics (title, cefr_level, filename) VALUES (?, ?, ?)",
                           (title, cefr_level, filename))
            conn.commit()
            conn.close()

            message = "Konu anlatımı başarıyla yüklendi."
        else:
            message = "Sadece PDF formatı kabul edilmektedir."

    return render_template("upload_pdf.html", message=message)
# Ana sayfa
@app.route('/')
def index():
    return render_template('index.html')

# ADMİN GİRİŞİ
from captcha.image import ImageCaptcha
import random
import string

from captcha.image import ImageCaptcha
import random
import string

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = ""
    captcha_code = session.get('captcha_code')

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        captcha_input = request.form.get('captcha', '')

        if not captcha_input or captcha_input.lower() != (captcha_code or "").lower():
            error = "Güvenlik kodu yanlış."
        else:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM admins WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()

            if result and check_password_hash(result[0], password):
                session['admin'] = username
                return redirect('/admin/dashboard')
            else:
                error = "Hatalı kullanıcı adı veya şifre."

    # Her giriş sayfasında yeni CAPTCHA üret
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    image = ImageCaptcha()
    image.write(captcha_text, 'static/captcha.png')
    session['captcha_code'] = captcha_text

    return render_template('admin_login.html', error=error)


    # Her GET isteğinde veya hatada yeni CAPTCHA üret
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    image = ImageCaptcha()
    image.write(captcha_text, 'static/captcha.png')
    session['captcha_code'] = captcha_text

    return render_template('admin_login.html', error=error)


# ADMİN PANEL
@app.route('/admin/dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect('/admin/login')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    message = ""

    if request.method == 'POST':
        new_username = request.form['new_username']
        new_password = request.form['new_password']
        hashed_pw = generate_password_hash(new_password)

        try:
            cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                (new_username, hashed_pw)
            )
            conn.commit()
            message = "Yeni admin başarıyla eklendi!"
        except sqlite3.IntegrityError:
            message = "Bu isimde bir admin zaten var."

    cursor.execute("SELECT * FROM admins")
    admins = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', admins=admins, message=message)

# ADMİN ÇIKIŞ
@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('admin', None)
    return redirect('/admin/login')

#admin yetki alma
@app.route('/admin/remove', methods=['POST'])
def remove_admin():
    if 'admin' not in session:
        return redirect('/admin/login')

    username_to_remove = request.form['username']

    # Kendini silemesin
    if username_to_remove == session['admin']:
        return redirect('/admin/dashboard')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM admins WHERE username = ?", (username_to_remove,))
    conn.commit()
    conn.close()

    return redirect('/admin/dashboard')
#soru ekleme
@app.route('/admin/add-question', methods=['GET', 'POST'])
def add_question():
    if 'admin' not in session:
        return redirect('/admin/login')

    message = ""

    if request.method == 'POST':
        question = request.form['question']
        a = request.form['option_a']
        b = request.form['option_b']
        c = request.form['option_c']
        d = request.form['option_d']
        correct = request.form['correct']
        grammar = request.form['grammar']
        level = request.form['level']

        conn = sqlite3.connect('questions.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO questions (
                question_text, option_a, option_b, option_c, option_d,
                correct_option, grammar_topic, cefr_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (question, a, b, c, d, correct, grammar, level))
        conn.commit()
        conn.close()

        message = "Soru başarıyla eklendi!"

    return render_template('add_question.html', message=message)

@app.route('/admin/questions')
def view_questions():
    if 'admin' not in session:
        return redirect('/admin/login')

    # Sayfalama
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page

    # Filtre
    filter_level = request.args.get('level', '')

    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()

    # Filtre varsa sorguyu ona göre yap
    if filter_level:
        cursor.execute("SELECT COUNT(*) FROM questions WHERE cefr_level = ?", (filter_level,))
        total_questions = cursor.fetchone()[0]
        cursor.execute("""
            SELECT * FROM questions WHERE cefr_level = ?
            LIMIT ? OFFSET ?
        """, (filter_level, per_page, offset))
    else:
        cursor.execute("SELECT COUNT(*) FROM questions")
        total_questions = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM questions LIMIT ? OFFSET ?", (per_page, offset))

    questions = cursor.fetchall()
    conn.close()

    total_pages = (total_questions + per_page - 1) // per_page

    return render_template(
        'view_questions.html',
        questions=questions,
        page=page,
        total_pages=total_pages,
        filter_level=filter_level
    )
@app.route('/admin/delete-question', methods=['POST'])
def delete_question():
    if 'admin' not in session:
        return redirect('/admin/login')

    question_id = request.form['question_id']
    page = request.form.get('page', 1)
    level = request.form.get('level', '')

    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM questions WHERE id = ?", (question_id,))
    conn.commit()
    conn.close()

    return redirect(f"/admin/questions?page={page}&level={level}")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO learners (full_name, username, password_hash)
                VALUES (?, ?, ?)""",
                (full_name, username, hashed_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Bu kullanıcı adı zaten var.")
        conn.close()
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, full_name, password_hash, current_level FROM learners WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and check_password_hash(result[2], password):
            session['learner_id'] = result[0]
            session['full_name'] = result[1]
            session['current_level'] = result[3]
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Hatalı kullanıcı adı veya şifre.")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'learner_id' not in session:
        return redirect('/login')

    # Seviyesi yoksa test başlat
    if session.get('current_level') is None:
        return redirect('/placement-test')

    # Aksi halde hoş geldin ekranı
    return render_template(
        'dashboard.html',
        full_name=session.get('full_name'),
        level=session.get('current_level')
    )

#seviye ölçme
from flask import session
import random

CEFR_LEVELS = ["A1", "A2", "B1", "B2", "C1"]

@app.route('/placement-test', methods=['GET', 'POST'])
def placement_test():
    if 'learner_id' not in session:
        return redirect('/login')

    # Test başlatılmadıysa sıfırdan başla
    if 'test_state' not in session:
        session['test_state'] = {
            'current_level': 'A2',
            'correct_counts': {level: 0 for level in CEFR_LEVELS},
            'wrong_streak': 0,
            'question_count': 0
        }

    state = session['test_state']
    current_level = state['current_level']

    if request.method == 'POST':
        selected = request.form.get('answer')
        correct = session.get('correct_answer')
        state['question_count'] += 1

        if selected == correct:
            state['correct_counts'][current_level] += 1
            state['wrong_streak'] = 0

            # 3 doğru varsa test biter
            if state['correct_counts'][current_level] >= 3:
                session['current_level'] = current_level
                session.pop('test_state', None)
                learner_id = session['learner_id']

                conn = sqlite3.connect('users.db')
                cursor = conn.cursor()
                cursor.execute("UPDATE learners SET current_level = ? WHERE id = ?", (current_level, learner_id))
                conn.commit()
                conn.close()

                return redirect('/my-level')
            else:
                # doğruysa 1 üst seviye
                index = CEFR_LEVELS.index(current_level)
                if index < len(CEFR_LEVELS) - 1:
                    state['current_level'] = CEFR_LEVELS[index + 1]

        else:
            # yanlışsa tekrar aynı seviye, art arda 2 yanlışa dikkat
            state['wrong_streak'] += 1
            if state['wrong_streak'] >= 2:
                index = CEFR_LEVELS.index(current_level)
                if index > 0:
                    state['current_level'] = CEFR_LEVELS[index - 1]
                state['wrong_streak'] = 0

    # Max 15 soruda bitir
    if state['question_count'] >= 15:
        # En yüksek 3 doğru yapılan seviye
        if all(correct == 0 for correct in state['correct_counts'].values()):
         final_level = "A1"  # Hiçbir doğru yoksa otomatik A1
        else:
         final_level = max(
        state['correct_counts'],
        key=lambda level: (state['correct_counts'][level], CEFR_LEVELS.index(level))
    )
        session['current_level'] = final_level
        session.pop('test_state', None)

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE learners SET current_level = ? WHERE id = ?", (final_level, session['learner_id']))
        conn.commit()
        conn.close()

        return redirect('/my-level')

    # Yeni soru getir
    current_level = state['current_level']
    conn = sqlite3.connect('questions.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM questions WHERE cefr_level = ?", (current_level,))
    questions = cursor.fetchall()
    conn.close()

    question = random.choice(questions)
    session['correct_answer'] = question[6]  # A/B/C/D

    options = {
        'A': question[2],
        'B': question[3],
        'C': question[4],
        'D': question[5]
    }

    return render_template(
        'placement_test.html',
        question_text=question[1],
        options=options,
        current_number=state['question_count'] + 1,
        topic=question[7]  # grammar_topic
    )

@app.route('/my-level')
def my_level():
    if 'learner_id' not in session or 'current_level' not in session:
        return redirect('/login')

    level = session['current_level']

    level_descriptions = {
        'A1': [
            ("I can understand and use familiar everyday expressions and very basic phrases.", 
             "Günlük ifadeleri ve çok temel cümleleri anlayabilir ve kullanabilirim."),
            ("I can introduce myself and others.", 
             "Kendimi ve başkalarını tanıtabilirim."),
            ("I can ask and answer questions about personal details.", 
             "Kişisel bilgilerle ilgili sorular sorabilir ve cevaplayabilirim.")
        ],
        'A2': [
            ("I can communicate in simple and routine tasks.", 
             "Basit ve rutin görevlerde iletişim kurabilirim."),
            ("I can describe in simple terms aspects of my background and environment.", 
             "Geçmişim ve çevremle ilgili basit açıklamalar yapabilirim.")
        ],
        'B1': [
            ("I can deal with most situations likely to arise while travelling.", 
             "Seyahat ederken karşılaşılabilecek çoğu durumla başa çıkabilirim."),
            ("I can produce simple connected text on familiar topics.", 
             "Aşina olduğum konularla ilgili basit bağlantılı metinler üretebilirim.")
        ],
        'B2': [
            ("I can understand the main ideas of complex text.", 
             "Karmaşık metinlerin ana fikirlerini anlayabilirim."),
            ("I can interact with fluency and spontaneity.", 
             "Akıcı ve doğal şekilde iletişim kurabilirim."),
            ("I can produce clear, detailed text on a wide range of subjects.", 
             "Geniş bir konu yelpazesinde açık ve ayrıntılı metinler yazabilirim.")
        ],
        'C1': [
            ("I can express myself fluently and spontaneously.", 
             "Kendimi akıcı ve kendiliğinden ifade edebilirim."),
            ("I can use language flexibly for social and professional purposes.", 
             "Dili sosyal ve profesyonel ortamlarda esnek şekilde kullanabilirim."),
            ("I can formulate ideas and opinions with precision.", 
             "Fikir ve görüşlerimi açık ve doğru şekilde ifade edebilirim.")
        ]
    }

    descriptions = level_descriptions.get(level, [])

    return render_template(
        'my_level.html',
        level=level,
        descriptions=descriptions,
        full_name=session.get('full_name')
    )


@app.route('/lessons')
def lessons():
    if 'learner_id' not in session:
        return redirect('/login')

    user_level = session.get('current_level', 'A1')
    cefr_levels = ['A1', 'A2', 'B1', 'B2', 'C1']

    # user_level + bir üst seviye
    index = cefr_levels.index(user_level)
    suggested_levels = [user_level]
    if index + 1 < len(cefr_levels):
        suggested_levels.append(cefr_levels[index + 1])

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Önerilen konular (seviye ve bir üstü)
    placeholders = ','.join(['?'] * len(suggested_levels))
    query = f"SELECT * FROM pdf_topics WHERE cefr_level IN ({placeholders})"
    cursor.execute(query, suggested_levels)

    suggested = cursor.fetchall()

    # Tüm PDF'ler
    cursor.execute("SELECT * FROM pdf_topics")
    all_pdfs = cursor.fetchall()

    conn.close()

    return render_template("lessons.html", suggested=suggested, all_pdfs=all_pdfs, selected_filter="all")
@app.route('/lessons/filter')
def lessons_filter():
    if 'learner_id' not in session:
        return redirect('/login')

    level = request.args.get('level', 'all')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    if level == 'all':
        cursor.execute("SELECT * FROM pdf_topics")
    else:
        cursor.execute("SELECT * FROM pdf_topics WHERE cefr_level = ?", (level,))
    filtered_pdfs = cursor.fetchall()

    # Yine önerilenler gösterilsin
    user_level = session.get('current_level', 'A1')
    cefr_levels = ['A1', 'A2', 'B1', 'B2', 'C1']
    index = cefr_levels.index(user_level)
    suggested_levels = [user_level]
    if index + 1 < len(cefr_levels):
        suggested_levels.append(cefr_levels[index + 1])
    cursor.execute("SELECT * FROM pdf_topics WHERE cefr_level IN (?, ?)", tuple(suggested_levels))
    suggested = cursor.fetchall()

    conn.close()

    return render_template("lessons.html", suggested=suggested, all_pdfs=filtered_pdfs, selected_filter=level)


@app.route('/admin/materials')
def admin_materials():
    if 'admin' not in session:
        return redirect('/admin/login')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pdf_topics ORDER BY cefr_level ASC")
    materials = cursor.fetchall()
    conn.close()

    return render_template("admin_materials.html", materials=materials)
@app.route('/admin/delete-pdf/<int:id>', methods=['POST'])
def delete_pdf(id):
    if 'admin' not in session:
        return redirect('/admin/login')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # önce dosya adını alalım
    cursor.execute("SELECT filename FROM pdf_topics WHERE id = ?", (id,))
    result = cursor.fetchone()

    if result:
        filename = result[0]
        filepath = os.path.join('static/pdfs', filename)
        if os.path.exists(filepath):
            os.remove(filepath)

        cursor.execute("DELETE FROM pdf_topics WHERE id = ?", (id,))
        conn.commit()

    conn.close()
    return redirect('/admin/materials')

@app.route('/retest', methods=['POST'])
def retest():
    if 'learner_id' not in session:
        return redirect('/login')

    learner_id = session['learner_id']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE learners SET current_level = NULL WHERE id = ?", (learner_id,))
    conn.commit()
    conn.close()

    # test durumu da sıfırlanmalı
    session.pop('current_level', None)
    session.pop('test_state', None)

    return redirect('/placement-test')

if __name__ == '__main__':
    app.run(debug=True)
