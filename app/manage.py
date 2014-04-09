#!/usr/bin/env python
import sys

from flask.ext.script import Server, Manager, Shell

sys.path.append('..')

from app import app, db, models, Base, engine


manager = Manager(app)
manager.add_command('runserver', Server(host="0.0.0.0"))
manager.add_command('shell', Shell(make_context=lambda: {
    'app': app,
    'db': db,
    'models': models
}))
#server = Server(host="0.0.0.0", port=5000)


@manager.command
def syncdb():
    from app import models
    db.create_all()
    Base.metadata.create_all(bind=engine)

if __name__ == '__main__':
    manager.run()
