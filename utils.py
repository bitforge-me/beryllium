import json

def extract_invoice_id(logger, attachment):
    try:
        data = json.loads(attachment)
        if "invoice_id" in data:
            return data["invoice_id"]
    except Exception as ex:
        logger.error(f"extract_invoice_id: {ex.message}")
    return None

