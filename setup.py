from setuptools import setup, find_packages

setup(
    name="leatt",
    version="0.1.0",
    description="Data Leak Prevention for individuals - Monitor processes to detect data exfiltration",
    author="Leatt Team",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "psutil>=5.9.0",
        "watchdog>=3.0.0",
        "pyyaml>=6.0",
        "sqlalchemy>=2.0.0",
        "pystray>=0.19.0",
        "Pillow>=10.0.0",
        "plyer>=2.1.0",
    ],
    extras_require={
        "web": [
            "fastapi>=0.109.0",
            "uvicorn>=0.27.0",
            "jinja2>=3.1.0",
        ],
        "ml": [
            "scikit-learn>=1.4.0",
            "numpy>=1.26.0",
            "joblib>=1.3.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "leatt=main:main",
        ],
    },
)
