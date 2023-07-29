import jwt from "jsonwebtoken"; 
export const verifyToken=async(req,res,next)=>{
    try{
        let token = req.header("Authorization");
        if(!token){
            return res.status(403).send("Access denied");

        }
        if(token.startsWith("Bearer ")){
            token=token.slice(7,token.length).trimLeft();//This
            // checks if the JWT is sent with the "Bearer " 
            //scheme, which is a common convention for including JWTs in the "Authorization" header. If so, it removes the "Bearer " prefix from the token string.
        }
        const verified =jwt.verify(token,process.env.JWT_SECRET);
        req.user=verified;
        next();
    }catch(err){
        res.status(500).json({error:err.message});
    }
};