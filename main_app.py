from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
import config

app = Flask(__name__)
app.config.from_object(config.Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)


@app.route('/v1/')
def hello():
    return 'hello'


if __name__ == '__main__':
    db.init_app(app)
    migrate.init_app(app, db)
    app.run('localhost', 5000, app.config["DEBUG"])
