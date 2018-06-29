import base58

def extract_invoice_id(attachment):
    data = base58.b58decode(attachment)
    try:
        data = json.loads(data)
        return data["invoice_id"]
    except:
        return None

