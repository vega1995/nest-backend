
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import {CreateUserDto,UpdateAuthDto,RegisterUserDto,LoginDto} from './dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService 
  ) {}



  async create(createAuthDto: CreateUserDto): Promise<User> {

    // const newUser=new this.userModel(createAuthDto);
    // return newUser.save();

    try {

      const {password, ...userData}=createAuthDto;
      const newUser=new this.userModel({
        password: bcryptjs.hashSync(password,10),
        ...userData
      });

       await newUser.save();

       const {password:_, ...user}=newUser.toJSON();

       return user;

    //3 Generar token de JWT

    //4 Retornar el usuario



      
    } catch (error) {
      if (error.code === 11000) throw new BadRequestException(`${createAuthDto.email} already exists`);
      throw  new InternalServerErrorException('Internal Server Error');
      
    }

  }



  async login(loginDto:LoginDto): Promise<LoginResponse> {


    const {email, password}=loginDto;
    const user= await this.userModel.findOne({email});
    if (!user) throw new UnauthorizedException('No Valid Credentials');
    if (!bcryptjs.compareSync(password, user.password)) throw new UnauthorizedException('No Valid Credentials');

    //Generar JWT

    const {password:_, ...rest}=user.toJSON();
    
    
    return {user:rest,token: this.getJWToken({id:user.id})};
  }


  async register(registerUserDto:RegisterUserDto):Promise<LoginResponse>{
    const user =await this.create(registerUserDto);


    return {user,token: this.getJWToken({id:user._id})};

  }




  findAll():Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id:string):Promise<User>{
    
    const user=await this.userModel.findById(id);
    const {password:_, ...rest}=user.toJSON();
    return rest;

  } 

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWToken(payload:JwtPayload){
    const token=this.jwtService.sign(payload);
    return token;

  }

}
