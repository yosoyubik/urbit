import React, { Component } from 'react';
import classnames from 'classnames';
import _ from 'lodash';

import { Message } from '/components/lib/message';
import { ChatTabBar } from '/components/lib/chat-tabbar';
import { ChatInput } from '/components/lib/chat-input';


export class ChatScreen extends Component {
  constructor(props) {
    super(props);

    this.state = {
      station: '/' + props.match.params.station,
      numPeople: 0,
      numPages: 1,
      scrollLocked: false,
    };

    this.pendingQueue = props.pendingMessages;

    this.hasAskedForMessages = false;
    this.onScroll = this.onScroll.bind(this);

    /*this.updateReadInterval = setInterval(
      this.updateReadNumber.bind(this),
      1000
    );*/
  }

  componentDidMount() {
    this.updateNumPeople();
    //this.updateReadNumber();
  }

  componentWillUnmount() {
    if (this.updateReadInterval) {
      clearInterval(this.updateReadInterval);
      this.updateReadInterval = null;
    }
  }

  componentDidUpdate(prevProps, prevState) {
    const { props, state } = this;

    if (prevProps.match.params.station !== props.match.params.station) {
      console.log('switched circle');
      this.hasAskedForMessages = false;

      clearInterval(this.updateReadInterval);

      this.setState({
        station: "/" + props.match.params.station,
        numPeople: 0,
        scrollLocked: false
      }, () => {
        this.updateNumPeople();
        this.scrollToBottom();
        this.updateReadInterval = setInterval(
          this.updateReadNumber.bind(this),
          1000
        );
        this.updateReadNumber();
      });
    } else if (!(state.station in props.inbox)) {
      props.history.push('/~chat');
    }
  }

  updateReadNumber() {
    const { props, state } = this;

    // TODO
    return;
    let internalCircle = 'hall-internal-' + state.circle;
    let internalStation = `~${window.ship}/${internalCircle}`;

    let internalConfig = props.configs[internalStation] || false;
    let regularConfig = props.configs[state.station] || false;

    let config = internalConfig || regularConfig;
    let messages = props.envelopes;

    let lastMsgNum = (messages.length > 0) ?
      ( messages[messages.length - 1].num + 1 ) : 0;

    if (config && config.red < lastMsgNum) {
      if (internalConfig) {
        props.api.read(internalCircle, lastMsgNum);
      } else {
        props.api.read(state.circle, lastMsgNum);
      }
    }
  }

  askForMessages() {
    const { props, state } = this;
    let messages = props.messages;
    
    if (state.numPages * 50 < props.messages.length - 200 ||
        this.hasAskedForMessages) {
      return;
    }

    if (messages.length > 0) {
      let end = messages[0].num;
      if (end > 0) {
        let start = ((end - 400) > 0) ? end - 400 : 0;

        this.hasAskedForMessages = true;

        console.log('fetching new messages');

        props.subscription.fetchMessages(state.station, start, end - 1);
      }
    }
  }

  scrollToBottom() {
    if (!this.state.scrollLocked && this.scrollElement) {
      this.scrollElement.scrollIntoView({ behavior: 'smooth' });
    }
  }

  onScroll(e) {
    if (navigator.userAgent.includes('Safari') &&
      navigator.userAgent.includes('Chrome')) {
      // Google Chrome
      if (e.target.scrollTop === 0) {
        this.setState({
          numPages: this.state.numPages + 1,
          scrollLocked: true
        }, () => {
          this.askForMessages();
        });
      } else if (
          (e.target.scrollHeight - Math.round(e.target.scrollTop)) ===
          e.target.clientHeight
      ) {
        this.setState({
          numPages: 1,
          scrollLocked: false
        });
      }
    } else if (navigator.userAgent.includes('Safari')) {
      // Safari
      if (e.target.scrollTop === 0) {
        this.setState({
          numPages: 1,
          scrollLocked: false
        });
      } else if (
          (e.target.scrollHeight + Math.round(e.target.scrollTop)) ===
          e.target.clientHeight
      ) {
        this.setState({
          numPages: this.state.numPages + 1,
          scrollLocked: true
        }, () => {
          this.askForMessages();
        });
      }
    } else {
      console.log('Your browser is not supported.');
    }
  }

  updateNumPeople() {
    return;
    let conf = this.props.configs[this.state.station] || {};
    let sis = _.get(conf, 'con.sis');
    let numPeople = !!sis ? sis.length : 0;
    if (numPeople !== this.state.numPeople) {
      this.setState({ numPeople });
    }
  }

  render() {
    const { props, state } = this;

    console.log(props.mailbox);
    let messages = props.envelopes.slice(0);
    
    let lastMsgNum = (messages.length > 0) ?
      messages.length : 0;

    if (messages.length > 50 * state.numPages) {
      messages = messages
        .slice(messages.length - (50 * state.numPages), messages.length);
    }

    let reversedMessages = messages.reverse();
    let chatMessages = reversedMessages.map((msg, i) => {
      // Render sigil if previous message is not by the same sender
      let aut = ['author'];    

      return (
        <Message
          key={Math.random()}
          msg={msg}
          renderSigil={true}
          paddingTop={0}
          paddingBot={0} />
      );
    });

    return (
      <div key={state.station}
        className="h-100 w-100 overflow-hidden flex flex-column">
        <div className='pl3 pt2 bb'>
          <h2>{state.station}</h2>
          <ChatTabBar {...props}
            station={state.station}
            numPeers={0} />
        </div>
        <div
          className="overflow-y-scroll pt3 pb2 flex flex-column-reverse"
          style={{ height: 'calc(100% - 157px)', resize: 'vertical' }}
          onScroll={this.onScroll}>
          <div ref={ el => { this.scrollElement = el; }}></div>
          {chatMessages}
        </div>
        <ChatInput
          api={props.api}
          numMsgs={lastMsgNum}
          station={state.station}
          security={'channel'}
          placeholder='Message...' />
      </div>
    )
  }
}
