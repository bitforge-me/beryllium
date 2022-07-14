from models import Setting
from sqlalchemy.orm.session import Session


def set_value(db_session: Session, keyname: str, value: str):
    setting = Setting.query.filter(Setting.key == keyname).first()
    if not setting:
        setting = Setting(keyname, value)
    else:
        setting.value = value
    db_session.add(setting)


def get(keyname: str) -> Setting | None:
    return Setting.query.filter(Setting.key == keyname).first()


def get_value(keyname: str):
    setting = get(keyname)
    if setting:
        return setting.value
    return None


def get_value_default(keyname: str, default: str):
    value = get_value(keyname)
    if value is not None:
        return value
    return default
