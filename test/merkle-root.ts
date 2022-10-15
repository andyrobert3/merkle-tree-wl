import { expect } from "chai";
import { ethers } from "hardhat";
import keccak256 from "keccak256";
import { MerkleTree } from "merkletreejs";

// Mimics the solidity abi.encodePacked() function
function encodeLeaf(address: string, spots: number) {
	return ethers.utils.defaultAbiCoder.encode(
		["address", "uint64"],
		[address, spots]
	);
}

describe("Check if Merkle Root is working", () => {
	it("Should verify if given address is whitelisted", async () => {
		const [owner, addr1, addr2, addr3, addr4, addr5] =
			await ethers.getSigners();

		const list = [
			encodeLeaf(owner.address, 2),
			encodeLeaf(addr1.address, 2),
			encodeLeaf(addr2.address, 2),
			encodeLeaf(addr3.address, 2),
			encodeLeaf(addr4.address, 2),
			encodeLeaf(addr5.address, 2),
		];

		// Create the Merkle Tree using the hashing algorithm `keccak256`
		// Make sure to sort the tree so that it can be produced deterministically regardless
		// of the order of the input list
		const merkleTree = new MerkleTree(list, keccak256, {
			hashLeaves: true,
			sortPairs: true,
		});

		// Compute the Merkle Root
		const root = merkleTree.getHexRoot();

		const whitelist = await ethers.getContractFactory("Whitelist");
		const Whitelist = await whitelist.deploy(root);
		await Whitelist.deployed();

		// Compute the Merkle Proof of the owner address (0'th item in list)
		// off-chain. The leaf node is the hash of that value.
		const leaf = keccak256(list[0]);
		const proof = merkleTree.getHexProof(leaf);

		// Provide the Merkle Proof to the contract, and ensure that it can verify
		// that this leaf node was indeed part of the Merkle Tree
		// Check if proof is valid or forged
		let verified = await Whitelist.checkInWhitelist(proof, 2);
		expect(verified).to.equal(true);

		// Provide an invalid Merkle Proof to the contract, and ensure that
		// it can verify that this leaf node was NOT part of the Merkle Tree
		verified = await Whitelist.checkInWhitelist([], 2);
		expect(verified).to.equal(false);
	});
});
