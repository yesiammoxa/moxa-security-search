# كشف النظام تلقائياً
system = platform.system()  # "Windows", "Linux", "Darwin"

# تثبيت مختلف لكل نظام
if system == "Windows":
    # تثبيت بدون --user (للويندوز)
elif system == "Linux":
    # تثبيت بـ --user (للتجنب sudo)