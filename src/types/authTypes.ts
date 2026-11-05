// Lo que el access token lleva de cada rol: alcanza para decidir el acceso
// sin ir a Mongo. Se arma en el login y en cada refresh.
export type TokenRole = {
	id: string;
	name: string;
	userType: string;
	permissions: { read: boolean; write: boolean };
};

export type AuthUser = {
	id: string;
	username: string;
	roles: TokenRole[];
};
