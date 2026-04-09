from wardline.decorators import privileged_operation

@privileged_operation
def delete_user(user_id):
    check_permission(user_id)
    db.delete(user_id)
