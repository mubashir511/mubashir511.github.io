import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # search buy table
    search_buy = db.execute("SELECT * FROM buy WHERE id=:id", id=session["user_id"])
    # find the max length of the search data
    search_len = len(search_buy)

    # Search cash table for remaing cash in hand
    search_users = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])

    for i in range(search_len):

        # Get latest price of the shares
        share_price = lookup(search_buy[i]['symbol'])

        # compare the latest price with price save in the table
        if share_price['price'] != search_buy[i]['price']:

            print("Update price of the shares")
            print(search_buy[i]['symbol'])
            print(f"old price: {search_buy[i]['price']}")
            print(f"new price: {share_price['price']}")

            # update buying data into buy table
            db.execute("UPDATE buy SET price=:price, total=:total WHERE id=:id AND symbol=:symbol", price=share_price['price'],
                       total=share_price['price']*float(search_buy[i]['shares']), id=search_buy[i]['id'], symbol=search_buy[i]['symbol'])

    # update the grand total
    totals = db.execute("SELECT total FROM buy WHERE id=:id", id=session["user_id"])
    big_total = 0
    for i in range(search_len):
        big_total += totals[i]['total']

    return render_template("index.html", search_buy=search_buy, search_len=search_len, search_users=search_users, big_total=big_total)


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("symbol"):
            return apology("Missing Symbol")

        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("INVALID SYMBOL")

        return render_template("quoted.html", name=quote['name'], symbol=quote['symbol'], price=quote['price'])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", 403)

        # Ensure share quantity was submitted
        if not request.form.get("shares"):
            return apology("missing shares", 403)

        quote = lookup(request.form.get("symbol"))
        if not quote:
            return apology("INVALID SYMBOL")

        # Check the share field has a number
        if not (request.form.get("shares")).isdigit():
            return apology("shares must be an integer number", 400)

        # number of shares user would like to purchase
        shares = float(request.form.get("shares"))

        # render an apology if the input is not a positive integer
        if shares < 1:
            return apology("shares must be a posative integer", 400)

        isfloat = shares % int(shares)
        if isfloat != 0:
            return apology("shares must be an integer number", 400)

        # Can the user afford the stock
        # Find the cash in hand
        cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
        userName = db.execute("SELECT username FROM users WHERE id=:id", id=session["user_id"])

        if (quote['price']*(float(request.form.get("shares")))) >= (cash[0]["cash"]):
            return("can't afford", 403)

        # check is table is empty
        chk_empty = db.execute("SELECT 1 FROM buy")
        if not chk_empty:
            db.execute("INSERT INTO buy (id, username, companyName, symbol, shares, price, total) VALUES(:id, :username, :companyName, :symbol, :shares, :price, :total)",
                       username=userName[0]["username"],
                       companyName=quote['name'],
                       symbol=quote['symbol'],
                       shares=request.form.get("shares"),
                       price=quote['price'],
                       total=quote['price']*float(request.form.get("shares")),
                       id=session["user_id"])
        else:
            # Search if the company share user is asking is already present(in hand)
            search = db.execute("SELECT * FROM buy WHERE id =:id AND symbol =:symbol",
                                id=session["user_id"], symbol=request.form.get("symbol"))

            if not search:
                db.execute("INSERT INTO buy (id, username, companyName, symbol, shares, price, total) VALUES(:id, :username, :companyName, :symbol, :shares, :price, :total)",
                           username=userName[0]["username"],
                           companyName=quote['name'],
                           symbol=quote['symbol'],
                           shares=request.form.get("shares"),
                           price=quote['price'],
                           total=quote['price']*float(request.form.get("shares")),
                           id=session["user_id"])

            else:
                # update buying data into buy table
                check = db.execute("UPDATE buy SET shares=:shares, price=:price, total=:total WHERE id=:id AND symbol=:symbol",
                                   shares=(int(request.form.get("shares")) + int(search[0]["shares"])),
                                   price=quote['price'],
                                   total=quote['price']*(float(request.form.get("shares"))+float(search[0]['shares'])),
                                   id=session["user_id"],
                                   symbol=request.form.get("symbol"))

        # update the cash in hand
        db.execute("UPDATE users SET cash=:Cash where id=:id",
                   Cash=((cash[0]["cash"]) - (quote['price']*float(request.form.get("shares")))),
                   id=session["user_id"])

        price = lookup(request.form.get("symbol"))

        # update history
        db.execute("INSERT INTO history (id, symbol, shares, price) VALUES(:id, :symbol, :shares, :price)",
                   id=session["user_id"],
                   symbol=(request.form.get("symbol")),
                   shares=(request.form.get("shares")),
                   price=price['price'])

        flash("Bought!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # Get user name from html form
    get_username = request.args.get("username")

    # validate the username from database
    if not len(get_username) < 1:
        username = db.execute("SELECT * FROM users WHERE username=:username", username=get_username)

        if username:
            return jsonify(False)
        else:
            return jsonify(True)
    else:
        return jsonify(False)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure Confirm password is submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        print(((request.form.get("username")).isalnum()) or ((request.form.get("username")).isalpha()))

        # Ensure username is alphanumeric string
        if (((request.form.get("username")).isalnum()) or ((request.form.get("username")).isalpha())) == False:
            return apology("must provide aplhanumeric username", 403)

        # If passwords donot match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("must write same passward in both fields", 400)
        else:
            hashPass = generate_password_hash((request.form.get("password")), method='pbkdf2:sha256', salt_length=8)

        # check is table is empty
        chk_empty = db.execute("SELECT 1 FROM users")

        # If empty table
        if not chk_empty:
            db.execute("UPDATE SQLITE_SEQUENCE SET SEQ=0 WHERE NAME='users'")

        # Set id sequence
        max_id = db.execute("SELECT MAX(id) FROM buy")
        db.execute("UPDATE SQLITE_SEQUENCE SET SEQ=:id WHERE NAME='users'", id=max_id[0]['MAX(id)'])

        result = db.execute("INSERT INTO users (username,hash) VALUES(:username,:hash)",
                            username=request.form.get("username"),
                            hash=hashPass)

        if not result:
            return apology("username already taken", 400)

        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        session["user_id"] = rows[0]["id"]

        flash("Registered!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # search 'History' table
    search_history = db.execute("SELECT * FROM history WHERE id=:id", id=session["user_id"])
    # find the max length of the search data
    search_len = len(search_history)

    return render_template("history.html", search_history=search_history, search_len=search_len)


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change Password of user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # user ask to change username
        if request.form.get("select") == "username":
            return redirect("/changeUsername")

        # user ask to change password
        elif request.form.get("select") == "password":
            return redirect("/changePassword")

        # no input
        else:
            return apology("choose any option", 403)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("change.html")


@app.route("/changePassword", methods=["GET", "POST"])
@login_required
def changePassword():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("old_password"):
            return apology("must provide present password", 400)

        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must provide new password", 400)

        # Ensure Confirm password is submitted
        if not request.form.get("confirm_password"):
            return apology("must fill confirm password", 400)

        # Ensure Confirmation (both passwords are same)
        if (request.form.get("new_password")) != (request.form.get("confirm_password")):
            return apology("must confirm password", 400)

        # acquire hash value of present user
        present_password_hash = db.execute("SELECT hash FROM users WHERE id=:id",
                                           id=session["user_id"])

        # Ensure old password is correct
        if check_password_hash(present_password_hash[0]['hash'], request.form.get("old_password")):

            # Generate hash for new password
            new_password_hash = generate_password_hash((request.form.get("new_password")), method='pbkdf2:sha256', salt_length=8)

            # Update present hash value
            db.execute("UPDATE users SET hash=:hash WHERE id=:id",
                       id=session["user_id"],
                       hash=new_password_hash)
        else:
            return apology("Provide correct password", 400)

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changePassword.html")


@app.route("/changeUsername", methods=["GET", "POST"])
@login_required
def changeUsername():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("new_username"):
            return apology("must provide new username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure username is alphanumeric string
        if (((request.form.get("new_username")).isalnum()) or ((request.form.get("new_username")).isalpha())) == False:
            return apology("must provide aplhanumeric username", 403)

        # acquire hash value of present user
        password_hash = db.execute("SELECT hash FROM users WHERE id=:id",
                                   id=session["user_id"])

        # Ensure old password is correct
        if check_password_hash(password_hash[0]['hash'], request.form.get("password")):

            # Update present username from table
            db.execute("UPDATE users SET username=:username WHERE id=:id",
                       id=session["user_id"],
                       username=request.form.get("new_username"))
        else:
            return apology("Provide correct password", 400)

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changeUsername.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get('symbol'):
            return apology("missing symbol", 400)

        # Ensure share quantity was submitted
        if not request.form.get("shares"):
            return apology("missing shares", 400)

        # Check the share field has a number
        if not (request.form.get("shares")).isdigit():
            return apology("shares must be an integer number", 400)

        # number of shares user would like to purchase
        shares = float(request.form.get("shares"))

        # render an apology if the input is not a positive integer
        if shares < 1:
            return apology("shares must be a posative integer", 400)

        isfloat = shares % int(shares)
        if isfloat != 0:
            return apology("shares must be an integer number", 400)

        chk_symbol = db.execute("SELECT symbol FROM buy WHERE id=:id", id=session["user_id"])
        symbol_len = len(chk_symbol)
        key = 0

        for i in range(symbol_len):
            if chk_symbol[i]['symbol'] == (request.form.get('symbol')):
                key = 1

        if key != 1:
            return apology("invalid symbol", 400)

        if int(request.form.get("shares")) < 1:
            return apology("invalid shares value", 400)

        search_buy = db.execute("SELECT * FROM buy WHERE id=:id AND symbol=:symbol",
                                id=session["user_id"],
                                symbol=request.form.get("symbol"))

        # if asked shares are more than shares in hand
        if search_buy[0]['shares'] < int(request.form.get("shares")):
            return apology("too much shares", 400)

        # delete the table if asked shares are equal shares in hand
        elif search_buy[0]['shares'] == request.form.get("shares"):
            db.execute("DELETE FROM buy WHERE id=:id AND symbol=:symbol",
                       id=session["user_id"],
                       symbol=request.form.get("symbol"))

        # do changes in the tables if asked shares are less than shares in hand
        else:
            # update buying data into buy table
            db.execute("UPDATE buy SET shares=:shares, price=:price, total=:total WHERE id=:id AND symbol=:symbol",
                       price=search_buy[0]['price'],
                       total=(search_buy[0]['price']*(float(search_buy[0]['shares'])-float(request.form.get("shares")))),
                       shares=(search_buy[0]['shares']-int(request.form.get("shares"))),
                       id=session["user_id"], symbol=request.form.get("symbol"))

            # update cash in hand (users table)
            present_cash = db.execute("SELECT cash FROM users WHERE id=:id", id=session["user_id"])
            db.execute("UPDATE users SET cash=:cash WHERE id=:id",
                       id=session["user_id"],
                       cash=(present_cash[0]["cash"]+(float(request.form.get("shares"))*search_buy[0]['price'])))

            # update history
            db.execute("INSERT INTO history (id, symbol, shares, price) VALUES(:id, :symbol, :shares, :price)",
                       id=session["user_id"],
                       symbol=request.form.get("symbol"),
                       shares=int(request.form.get("shares"))*(-1),
                       price=(search_buy[0]['price']))

            flash("sold!")

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        symbols = db.execute("SELECT * FROM buy WHERE id=:id", id=session["user_id"])
        symbols_len = len(symbols)

        return render_template("sell.html", symbols=symbols, symbols_len=symbols_len)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
