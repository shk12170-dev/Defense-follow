def mask_name(v):
    return v[0] + "*" * (len(v) - 1) if len(v) > 1 else v


def mask_phone(v):
    parts = v.split("-")
    return f"{parts[0]}-****-{parts[-1]}" if len(parts) == 3 else "****"


def mask_email(v):
    local, _, domain = v.partition("@")
    return local[:2] + "***@" + domain


def mask_rrn(v):
    return v[:8] + "******" if len(v) >= 8 else "******"


def mask_address(v):
    return " ".join(v.split()[:2]) + " ***"


def masked(row):
    return {
        "id": row["id"],
        "name": mask_name(row["name"]),
        "phone": mask_phone(row["phone"]),
        "email": mask_email(row["email"]),
        "rrn": mask_rrn(row["rrn"]),
        "address": mask_address(row["address"]),
    }


def full(row):
    return {k: row[k] for k in ("id", "name", "phone", "email", "rrn", "address")}
