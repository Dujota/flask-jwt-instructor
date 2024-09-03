# Import the 'Flask' class from the 'flask' library.
from flask import Flask, jsonify, request
from dotenv import load_dotenv
import os
import psycopg2, psycopg2.extras
import jwt
import bcrypt
load_dotenv()
# Initialize Flask
# We'll use the pre-defined global '__name__' variable to tell Flask where it is.
app = Flask(__name__)

def get_db_connection():
    connection = psycopg2.connect(
                            host=os.getenv('POSTGRES_HOST'),
                            database=os.getenv('POSTGRES_DB_NAME'),
                            user=os.getenv('POSTGRES_USERNAME'),
    )
    return connection

# Define our route
# This syntax is using a Python decorator, which is essentially a succinct way to wrap a function in another function.
@app.route('/')
def index():
  return "Hello, world!"

@app.route('/sign-token', methods=['GET'])
def sign_token():
    user = {
        "id": 1,
        "username": "test",
        "password": "test"
    }

    token = jwt.encode(user, os.environ["JWT_SECRET"], algorithm="HS256")

    return jsonify({"token" : token})


@app.route('/verify-token', methods=['POST'])
def verify_token():
  try:
    token = request.headers.get("Authorization").split(" ")[1]

    decoded =  jwt.decode(token, os.getenv("JWT_SECRET"), algorithms="HS256")

    return jsonify({"user" : decoded})
  except Exception:
    return jsonify({"error" : "Invalid token"}), 401

@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        new_user_data = request.get_json()

        # extract the fields
        username = new_user_data["username"]
        password = new_user_data["password"]

        # connect to db
        connection = get_db_connection()
        cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        user_lookup_query = "SELECT * FROM users WHERE username = %s;"


        # run the find user query
        cursor.execute(user_lookup_query, (username,))
        existing_user = cursor.fetchone()

        # exit if the user exists with an error
        if existing_user:
            cursor.close()
            return jsonify({"error": "Something went wrong"}), 400

        # when user is new to us, scarmble the password, to get it ready for db save
        hashed_password = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())

        create_user_mutation = "INSERT INTO users (username, password) VALUES (%s, %s) RETURNING username;"

        # create the user
        cursor.execute(create_user_mutation, (username, hashed_password.decode('utf-8')))
        created_user = cursor.fetchone()
        connection.commit()


        connection.close()

        token = jwt.encode(created_user, os.environ["JWT_SECRET"], algorithm="HS256")

        return jsonify({"token" : token}), 201
    except Exception as error:
        return jsonify({"error": str(error)}), 401


@app.route('/auth/signin', methods=['POST'])
def signin():
    try:
      user_data = request.get_json()

      # extract the fields
      username = user_data["username"]
      password = user_data["password"]

      # connect to db
      connection = get_db_connection()
      cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

      user_lookup_query = "SELECT * FROM users WHERE username = %s;"

      # run the find user query
      cursor.execute(user_lookup_query, (username,))
      existing_user = cursor.fetchone()

      # exit if the user  does not exists with an error
      if existing_user is None:
          cursor.close()
          return jsonify({"error": "Something went wrong"}), 400

      # check if the password is correct
      password_is_valid = bcrypt.checkpw(bytes(password, 'utf-8'), bytes(existing_user["password"], 'utf-8'))
      # if not, return an error
      if not password_is_valid:
          return jsonify({"error": "Invalid Credentials"}), 401

      token = jwt.encode(existing_user, os.environ["JWT_SECRET"], algorithm="HS256")

      return jsonify({"token" : token})

    except Exception as e:
       return jsonify({"error": "Invalid credentials."}), 401
    finally:
       connection.close()

# Run our application, by default on port 5000
app.run()