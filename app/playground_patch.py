from flask import render_template_string

PLAYGROUND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🧪 OAuth Playground</title>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <style>
      body { font-family: system-ui, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; background: #000; color: #fff; }
      input, button { padding: 10px; margin: 5px; font-size: 16px; }
      button { background: #f7931a; border: none; color: white; cursor: pointer; }
      .matrix { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; }
    </style>
</head>
<body>
  <h1>🧪 HODLXXI OAuth2/OIDC Playground</h1>
  <p>Test the full OAuth flow</p>
  
  <div id="root"></div>

  <script type="text/babel">
    const { useState } = React;
    const App = () => {
      const [clientId, setClientId] = useState("playground-client");
      const startFlow = () => {
        const params = new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: "https://hodlxxi.com/playground",
          scope: "openid profile",
          state: Math.random().toString(36).substring(7),
          code_challenge_method: "S256",
          code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        });
        window.location = `/oauth/authorize?${params}`;
      };
      return (
        <div>
          <input value={clientId} onChange={e => setClientId(e.target.value)} placeholder="client_id" />
          <button onClick={startFlow}>Start OAuth Flow →</button>
        </div>
      );
    };
    ReactDOM.createRoot(document.getElementById('root')).render(<App />);
  </script>
</body>
</html>"""

@app.route("/playground")
def playground():
    return render_template_string(PLAYGROUND_HTML)
