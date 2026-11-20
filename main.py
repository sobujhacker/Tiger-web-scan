from dashboard import create_app

if __name__ == "__main__":
    app = create_app()
    print("TIGER WEB SCANNER V6")
    print("Open: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
