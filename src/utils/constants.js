export const UserRolesEnum = {
    ADMIN : "admin",
    PROJECT_ADMIN : "project_admin",
    MEMBER : "member"
}

export const TaskStatusEnum = {
    TODO : "todo",
    IN_PROGRESS : "in_progress",
    COMPLETED : "completed"
}

export const AvailableRoles = Object.values(UserRolesEnum)
export const AvailableTaskStatus = Object.values(TaskStatusEnum)