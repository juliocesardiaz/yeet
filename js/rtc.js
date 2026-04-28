import { replaceCredentials } from './signaling.js';

function extractFingerprint(sdp) {
  const m = sdp.match(/a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/);
  return m ? m[1] : null;
}

export class RTCManager {
  constructor() {
    this.pc = null;
    this.dc = null;
    this.onMessage = null;
    this.onStateChange = null;
  }

  _createPC() {
    this.pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
    });

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
      if (this.onStateChange) this.onStateChange('closed');
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
      const timeout = setTimeout(() => resolve(), 10000);
      this.pc.onicegatheringstatechange = () => {
        if (this.pc.iceGatheringState === 'complete') {
          clearTimeout(timeout);
          resolve();
        }
      };
    });
  }

  async createOffer() {
    this._createPC();

    const dc = this.pc.createDataChannel('yeet', { ordered: true });
    this._setupDataChannel(dc);

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription({ type: offer.type, sdp: await replaceCredentials(offer.sdp) });
    await this._waitForICE();

    return this.pc.localDescription.sdp;
  }

  async acceptOffer(sdp) {
    this._createPC();

    this.pc.ondatachannel = (e) => {
      this._setupDataChannel(e.channel);
    };

    await this.pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription({ type: answer.type, sdp: await replaceCredentials(answer.sdp) });
    await this._waitForICE();

    return this.pc.localDescription.sdp;
  }

  async acceptAnswer(sdp) {
    await this.pc.setRemoteDescription({ type: 'answer', sdp });
  }

  send(data) {
    if (this.dc && this.dc.readyState === 'open') {
      this.dc.send(data);
    }
  }

  // Returns { local, remote } fingerprint hex strings as they appear in the
  // negotiated SDPs. Both peers compute SAS over these — a MITM substituting
  // certs at one or both legs makes the SAS values diverge.
  getFingerprints() {
    const localSdp = this.pc?.localDescription?.sdp;
    const remoteSdp = this.pc?.remoteDescription?.sdp;
    if (!localSdp || !remoteSdp) return null;
    const local = extractFingerprint(localSdp);
    const remote = extractFingerprint(remoteSdp);
    if (!local || !remote) return null;
    return { local, remote };
  }

  disconnect() {
    // Detach callbacks first so late-firing events from close() don't leak
    // into the next pairing session.
    this.onMessage = null;
    this.onStateChange = null;
    if (this.dc) {
      this.dc.onopen = this.dc.onclose = this.dc.onmessage = null;
      this.dc.close();
      this.dc = null;
    }
    if (this.pc) {
      this.pc.onconnectionstatechange = null;
      this.pc.onicegatheringstatechange = null;
      this.pc.ondatachannel = null;
      this.pc.close();
      this.pc = null;
    }
  }
}
