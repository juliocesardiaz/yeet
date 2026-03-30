export class RTCManager {
  constructor() {
    this.pc = null;
    this.dc = null;
    this.onMessage = null;
    this.onStateChange = null;
  }

  _createPC() {
    this.pc = new RTCPeerConnection({ iceServers: [] });

    this.pc.onconnectionstatechange = () => {
      const state = this.pc.connectionState;
      if (this.onStateChange) this.onStateChange(state);
    };
  }

  _setupDataChannel(dc) {
    this.dc = dc;

    dc.onopen = () => {
      if (this.onStateChange) this.onStateChange('connected');
    };

    dc.onclose = () => {
      if (this.onStateChange) this.onStateChange('disconnected');
    };

    dc.onmessage = (e) => {
      if (this.onMessage) this.onMessage(e.data);
    };
  }

  _waitForICE() {
    return new Promise((resolve) => {
      if (this.pc.iceGatheringState === 'complete') {
        resolve();
        return;
      }
      this.pc.onicegatheringstatechange = () => {
        if (this.pc.iceGatheringState === 'complete') resolve();
      };
    });
  }

  async createOffer() {
    this._createPC();

    const dc = this.pc.createDataChannel('yeet', { ordered: true });
    this._setupDataChannel(dc);

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    await this._waitForICE();

    return mungeSDP(this.pc.localDescription.sdp);
  }

  async acceptOffer(sdp) {
    this._createPC();

    this.pc.ondatachannel = (e) => {
      this._setupDataChannel(e.channel);
    };

    await this.pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    await this._waitForICE();

    return mungeSDP(this.pc.localDescription.sdp);
  }

  async acceptAnswer(sdp) {
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
  }

  send(data) {
    if (this.dc && this.dc.readyState === 'open') {
      this.dc.send(data);
    }
  }

  disconnect() {
    if (this.dc) {
      this.dc.close();
      this.dc = null;
    }
    if (this.pc) {
      this.pc.close();
      this.pc = null;
    }
  }
}

function mungeSDP(sdp) {
  const dominated = [
    'a=extmap',
    'a=msid-semantic',
    'a=group:BUNDLE',
    'a=rtcp-mux',
    'a=rtcp:',
  ];

  return sdp
    .split('\r\n')
    .filter(line => !dominated.some(prefix => line.startsWith(prefix)))
    .join('\r\n');
}
