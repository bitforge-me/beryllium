from models import Setting

def set_value(db_session, keyname, value):
    setting = Setting.query.filter(Setting.key == keyname).first()
    if not setting:
        setting = Setting(keyname, value)
    else:
        setting.value = value
    db_session.add(setting)

def get_value(keyname, default):
    setting = Setting.query.filter(Setting.key == keyname).first()
    if not setting:
        return default
    return setting.value
