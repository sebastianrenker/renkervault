export type CallKind = 'audio' | 'video';

export type CallSignal =
  | { type: 'offer'; callId: string; kind: CallKind; sdp: string }
  | { type: 'answer'; callId: string; sdp: string }
  | { type: 'ice'; callId: string; candidate: RTCIceCandidateInit }
  | { type: 'hangup'; callId: string };

const ICE_SERVERS: RTCIceServer[] = [{ urls: 'stun:stun.l.google.com:19302' }];

export class CallSession {
  readonly callId: string;
  readonly peerId: string;
  readonly kind: CallKind;
  readonly pc: RTCPeerConnection;
  localStream: MediaStream | null = null;
  readonly remoteStream: MediaStream;
  onIceCandidate: (c: RTCIceCandidateInit) => void = () => {};
  onConnectionStateChange: (s: RTCPeerConnectionState) => void = () => {};
  onRemoteTrack: () => void = () => {};

  constructor(callId: string, peerId: string, kind: CallKind) {
    this.callId = callId;
    this.peerId = peerId;
    this.kind = kind;
    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.remoteStream = new MediaStream();
    this.pc.ontrack = (e) => {
      const tracks = e.streams[0] ? e.streams[0].getTracks() : [e.track];
      for (const t of tracks) this.remoteStream.addTrack(t);
      this.onRemoteTrack();
    };
    this.pc.onicecandidate = (e) => {
      if (e.candidate) this.onIceCandidate(e.candidate.toJSON());
    };
    this.pc.onconnectionstatechange = () => this.onConnectionStateChange(this.pc.connectionState);
  }

  async startLocalMedia(): Promise<void> {
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: true, video: this.kind === 'video',
    });
    for (const track of this.localStream.getTracks()) this.pc.addTrack(track, this.localStream);
  }

  async createOffer(): Promise<RTCSessionDescriptionInit> {
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    return offer;
  }

  async createAnswer(offerSdp: RTCSessionDescriptionInit): Promise<RTCSessionDescriptionInit> {
    await this.pc.setRemoteDescription(offerSdp);
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    return answer;
  }

  async applyAnswer(sdp: RTCSessionDescriptionInit): Promise<void> {
    await this.pc.setRemoteDescription(sdp);
  }

  async addIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
    try { await this.pc.addIceCandidate(candidate); } catch {}
  }

  setMuted(muted: boolean): void {
    this.localStream?.getAudioTracks().forEach((t) => { t.enabled = !muted; });
  }

  setCameraOff(off: boolean): void {
    this.localStream?.getVideoTracks().forEach((t) => { t.enabled = !off; });
  }

  close(): void {
    this.pc.getSenders().forEach((s) => s.track?.stop());
    this.localStream?.getTracks().forEach((t) => t.stop());
    this.pc.close();
  }
}

export function newCallId(): string {
  return crypto.randomUUID();
}
