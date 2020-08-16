def getbarcodeimage(self, sessionId):
   type = "IL"
   BarcodeURL = "%s/applications/%s/barcodes?session=%s&token=%s&type=%s" % (Constant.API_URL, Constant.APP_API_KEY, sessionId, self.appT.get(), type)
   barcode_image = requests.get(BarcodeURL)
   response = barcode_image.json()['barcodeimage']
   if barcode_image.status_code == 'EXPIRED_TOKEN':
       self.appT.invalidate()
       self.trackerValidation(trackerid, username)
   else:
       response
   return response


def GetBarcode():
      sessionId = uuid.uuid4()
      session['uid'] = str(sessionId)
      result = appService.getbarcodeimage(sessionId)
      print("AAAA")
      return result
app.jinja_env.globals.update(scanbarcode=GetBarcode)

@app.route('/login-post-url', methods=['POST'])
def empty_view():
   sessionID = request.headers.get('session')
   username = request.headers.get('username')
   trackerID = request.headers.get('tracker')
   result = appService.trackerValidation(trackerID, username)
   if result == True :
      socketio.emit('message', {'result': 'OK'}, room=clients[sessionID])
   else: print("Tracker is invalid.")
   content = ""
   return content, status.HTTP_200_OK

@socketio.on('connect')
def connected():
   socket_id = request.sid
   clients[session['uid']] = socket_id

@socketio.on('disconnect')
def disconnected():
   del clients[session['uid']]
