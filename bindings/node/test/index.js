var nscrypto   = require('../build/Release/nscrypto');
var should     = require('should');

// Make a SlowBuffer from a normal Buffer
var SlowBuffer = require('buffer').SlowBuffer;
function MakeSlowBuffer(buffer) {
  var slow = new SlowBuffer(buffer.length);
  buffer.copy(slow, 0, 0, buffer.length);
  return slow;
}

// Test values.
var apiKey  = 'client_id';
var srvId   = 'server_id';
var data    = 'receipe for super secret sauce';
var prv     = Buffer('MCUCAQEEIDxLsSRwM29PV2LSgoNz/8eXrX0Sg/aXlWEnVYnm9zK7', 'base64');
var pub     = Buffer('A09kTbw7sNXYelunxoSVORzZ9aFiAPI0CA+ws2LX00Vg', 'base64');
var enc     = Buffer('B9qU8lP67XRPYkZ5y+oPvgp8XJVN+fXkV4gs7KZ9yVVjcHUzR+ZrWZ4ADRG9xQ==', 'base64');
var eph     = Buffer('A8De/10udHLK1CEvSQFTJs+n49/UZ8NrkmAIK5qQ3v1i', 'base64');

describe('nscrypto', function() {

  it('should have loaded properly', function() {
    should.exist(nscrypto);
  });

  describe('ec_keypair()', function() {
    var key;

    beforeEach(function() {
      key = nscrypto.ec_keypair();
    });

    it('should have generated a public key', function() {
      should.exist(key.public);
    });

    it('...with the right length', function() {
      key.public.length.should.equal( pub.length );
    });

    it('should have generated a private key', function() {
      should.exist(key.private);
    });

    it('...with the right length', function() {
      key.private.length.should.equal( prv.length );
    });

  });

  describe('{en,de}cryption', function() {

    describe('ecdh_client_encrypt()', function() {
      var data, enc;

      beforeEach(function() {
        data = Buffer('receipe for super secret sauce');
        enc  = nscrypto.ecdh_client_encrypt(prv, pub, apiKey, srvId, data);
      });

      it('should have returned an object', function() {
        enc.should.be.a.Object;
      });

      it('should have an "enc" property', function() {
        enc.should.have.property('enc');
      });

      it('...which should be at least as long as authentication tag', function() {
        enc.enc.length.should.greaterThan(16);
      });

      it('should have an "eph" property', function() {
        enc.should.have.property('eph');
      });

      it('...which should have length of a public key', function() {
        enc.eph.length.should.equal(pub.length);
      });
    });

    describe('device -> server', function() {
      var sk, rk; // Sender Key, Recipient Key
      var _data, enc, dec;

      before(function() {
        sk = nscrypto.ec_keypair();
        rk = nscrypto.ec_keypair();
      });

      beforeEach(function() {
        _data = Buffer('receipe for super secret sauce');
        enc   = nscrypto.ecdh_client_encrypt(sk.private, rk.public, apiKey, srvId, _data);
      });

      it('should decrypt data as server', function() {
        dec = nscrypto.ecdh_server_decrypt(rk.private, sk.public, apiKey, srvId, enc);
        dec.toString().should.equal(_data.toString());
      });

      it('should NOT decrypt data as device', function() {
        dec = nscrypto.ecdh_client_decrypt(rk.private, sk.public, apiKey, srvId, enc);
        dec.length.should.equal(0);
      });

      it('should decrypt data as server when provided with SlowBuffer arguments', function() {
        dec = nscrypto.ecdh_server_decrypt(MakeSlowBuffer(rk.private),
                                           MakeSlowBuffer(sk.public),
                                           apiKey,
                                           srvId,
                                           {
                                             "enc": MakeSlowBuffer(enc.enc),
                                             "eph": MakeSlowBuffer(enc.eph)
                                           });
        dec.toString().should.equal(_data.toString());
      });
    });

    describe('device <- server', function() {
      var sk, rk; // Sender Key, Recipient Key
      var _data, enc, dec;

      before(function() {
        sk = nscrypto.ec_keypair();
        rk = nscrypto.ec_keypair();
      });

      beforeEach(function() {
        _data = Buffer('receipe for super secret sauce');
        enc   = nscrypto.ecdh_server_encrypt(sk.private, rk.public, srvId, apiKey, _data);
      });

      it('should decrypt data as device', function() {
        dec = nscrypto.ecdh_client_decrypt(rk.private, sk.public, srvId, apiKey, enc);
        dec.toString().should.equal(_data.toString());
      });

      it('should NOT decrypt data as server', function() {
        dec = nscrypto.ecdh_server_decrypt(rk.private, sk.public, srvId, apiKey, enc);
        dec.length.should.equal(0);
      });

      it('should decrypt data as client when provided with SlowBuffer arguments', function() {
        dec = nscrypto.ecdh_client_decrypt(MakeSlowBuffer(rk.private),
                                           MakeSlowBuffer(sk.public),
                                           srvId,
                                           apiKey,
                                           {
                                            "enc": MakeSlowBuffer(enc.enc),
                                            "eph": MakeSlowBuffer(enc.eph)
                                           });
        dec.toString().should.equal(_data.toString());
      });
    });

    describe('test values', function() {
      var dec;

      it('should be able to decrypt test values', function() {
        should(function() {
          dec = nscrypto.ecdh_server_decrypt(prv, pub, "1234", "vpCloud", {"enc": enc, "eph": eph});
        }).not.throw();

        dec.toString().should.equal(data.toString());
      });
    });
  });
});
