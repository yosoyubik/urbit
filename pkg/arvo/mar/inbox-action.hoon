/-  *inbox
=,  dejs:format
|_  act=inbox-action
++  grab
  |%
  ++  noun  inbox-action
  ++  json  
    |=  jon=^json
    =<  (parse-inbox-action jon)
    |%
    ++  parse-inbox-action
      %-  of
      :~  [%create create]
          [%delete delete]
          [%message message]
          [%read read]
      ==
    ::
    ++  create
      %-  ot
      :~  [%path (su ;~(pfix net (more net urs:ab)))]
          [%owner (su ;~(pfix sig fed:ag))]
      ==
    ::
    ++  delete
      (ot [%path (su ;~(pfix net (more net urs:ab)))]~)
    ::
    ++  message
      %-  ot
      :~  [%path (su ;~(pfix net (more net urs:ab)))]
          [%envelope envelope]
      ==
    ::
    ++  read
      %-  ot
      :~  [%path (su ;~(pfix net (more net urs:ab)))]
          [%read ni]
      ==
    ++  envelope
      %-  ot
      :~  [%author (su ;~(pfix sig fed:ag))]
          [%when di]
          [%message so]
      ==
    ::
    --
  --
--
