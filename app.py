from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

# Import functions from helpers.py file
from helpers import *


# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope (separate for gmail and calendar APIs) allows for full modify/write
# access to the authenticated user's account and requires requests to use an SSL connection.
SCOPES_GMAIL = 'https://www.googleapis.com/auth/gmail.modify'
API_SERVICE_NAME_GMAIL = 'gmail'
API_VERSION_GMAIL = 'v1'

SCOPES_CAL = 'https://www.googleapis.com/auth/calendar'
API_SERVICE_NAME_CAL = 'calendar'
API_VERSION_CAL = 'v3'


# Configure application
app = Flask(__name__)

app.secret_key = 'II5l9oW0KmbyZgW88vzu'


@app.after_request
def after_request(response):
  response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
  response.headers["Expires"] = 0
  response.headers["Pragma"] = "no-cache"
  return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route("/", methods=["GET", "POST"])
def index():
  # If no login creditionals are stored in the Flask session, ask user to authorize account
  if 'credentials' not in flask.session:
    return redirect('authorize-gmail')

  # If user is authorized, then parse Gmail account for events in new messages to add to the calendar
  else:
    parseGmail()

    # Redirect to the load-calendar page after done parsing
    return redirect("/load-calendar")


@app.route("/load-calendar")
def load_calendar():
  # Obtain credentials from flask session to build calendar
  credentials = google.oauth2.credentials.Credentials(
  **flask.session['credentials'])
  cal = googleapiclient.discovery.build(
        API_SERVICE_NAME_CAL, API_VERSION_CAL, credentials=credentials)
  
  # Initialize allCalendars
  session["allCalendars"] = listEvents(cal)

  # Initialize calendar view to week
  session["currView"] = "week"

  # Initialize chosenCals to all indices in allCalendars
  session["chosenCals"] = [i for i in range(len(session["allCalendars"]))]

  # Redirect user to calendar
  return redirect("/calendar")


@app.route("/calendar", methods=["GET", "POST"])
def calendar():
  # Update view and currView
  view = request.args.get("view")
  if not view:
    view = session["currView"]
  else:
    session["currView"] = view
  
  # Get indices of calendars as ints from checkboxes
  if request.method == 'POST':
    session["chosenCals"] = [int(i) for i in request.form.getlist('filter')]
  
  # Make list of calendar names, codes, colors that the user wants to see
  chosenCals = [session["allCalendars"][i] for i in session["chosenCals"]]
  for cal in chosenCals:
    cal[1] = cal[1].replace("#", "%23")

  # Render calendar page
  return render_template("calendar.html", allCalendars=session["allCalendars"], month=(True if view == "month" else False), 
              agenda=(True if view == "agenda" else False), chosenCals=chosenCals, indices=session["chosenCals"])
  

# Authorization function from Gmail API
@app.route('/authorize-gmail')
def authorize_gmail():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow_gmail = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES_GMAIL)

  flow_gmail.redirect_uri = flask.url_for('oauth2callback_gmail', _external=True)


  authorization_url_gmail, state_gmail = flow_gmail.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state_gmail

  return redirect(authorization_url_gmail)

# Authorization callback function from Gmail API
@app.route('/oauth2callback-gmail')
def oauth2callback_gmail():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES_GMAIL, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback_gmail', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return redirect(url_for('index'))


# Authorization function from Google Calendar API
@app.route('/authorize-cal')
def authorize_cal():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow_cal = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES_CAL)

  flow_cal.redirect_uri = flask.url_for('oauth2callback_cal', _external=True)

  authorization_url_cal, state_cal = flow_cal.authorization_url(
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.
      access_type='offline',
      # Enable incremental authorization. Recommended as a best practice.
      include_granted_scopes='true')

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state_cal

  return redirect(authorization_url_cal)


#Authorization callback function from Google Calendar API
@app.route('/oauth2callback-cal')
def oauth2callback_cal():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES_CAL, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback_cal', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return redirect(url_for('index'))

# Revoke creditentials from Flask session (from Google API documentation)
@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' +
            'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
      params={'token': credentials.token},
      headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return('Credentials successfully revoked.')
  else:
    return('An error occurred.')


# Clear creditionals from Flask session (from Google API documentation)
@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return ('Credentials have been cleared.<br><br>')


def main():
  return redirect("/")


if __name__ == '__main__':
  app.run()

